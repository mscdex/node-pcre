#include <node.h>
#include <node_buffer.h>
#include <string.h>
#include <unordered_map>

#include "pcre.h"

#define WHAT_EXEC 0
#define WHAT_EXECALL 1
#define WHAT_TEST 2

#define FREE_INFO(info) {                           \
          if (info) {                               \
            if ((info)->ovector)                    \
              free((info)->ovector);                \
            (info)->ovector = NULL;                 \
            (info)->caplen = (info)->ovecsize = 0;  \
            if ((info)->extra) {                    \
              pcre_free_study((info)->extra);       \
              (info)->extra = NULL;                 \
            }                                       \
            if (!(info)->name_map.empty())          \
              (info)->name_map.clear();             \
          }                                         \
        }

using namespace node;
using namespace std;
using namespace v8;

static Persistent<FunctionTemplate> constructor;
static Persistent<String> erroffset_symbol;
static Persistent<String> errcode_symbol;
static Persistent<String> named_symbol;
static Persistent<String> err_fullinfo_symbol;

typedef unordered_multimap<int,const char*> NameMap;

struct re_info {
  re_info() : caplen(0),
              ovecsize(0),
              ovector(NULL),
              extra(NULL) {}

  int caplen;
  int ovecsize;
  int *ovector;

  NameMap name_map;

  pcre_extra *extra;
};

int getCapInfo(pcre *re, struct re_info *info) {
  unsigned char *name_table;
  int r, caplen, name_count, name_size;

  if (re) {
    // check for non-named captures
    r = pcre_fullinfo(re, info->extra, PCRE_INFO_CAPTURECOUNT, &caplen);
    if (r < 0)
      return r;

    if (caplen > 0) {
      // check for named captures
      r = pcre_fullinfo(re, info->extra, PCRE_INFO_NAMECOUNT, &name_count);
      if (r < 0)
        return r;

      if (name_count > 0) {
        r = pcre_fullinfo(re, info->extra, PCRE_INFO_NAMETABLE, &name_table);
        if (r < 0)
          return r;

        r = pcre_fullinfo(re, info->extra, PCRE_INFO_NAMEENTRYSIZE, &name_size);
        if (r < 0)
          return r;

        unsigned char *tabptr = name_table;
#ifndef _MSC_VER
        info->name_map.reserve(name_count);
#endif
        // TODO: convert second value from cstring to Persistent<String> as
        //       optimization during exec()?
        for (int i = 0; i < name_count; i++) {
          info->name_map.insert(
            NameMap::value_type((tabptr[0] << 8) | tabptr[1],
                                (const char*)(tabptr + 2))
          );
          tabptr += name_size;
        }
      }
    }

    info->caplen = caplen;
    info->ovecsize = (info->caplen + 1) * 3;
    info->ovector = (int*)malloc(info->ovecsize * sizeof(int));

    return 0;
  }
  // use positive value since PCRE uses negative numbers for their errors ...
  return 1;
}

class PCRE : public ObjectWrap {
  public:
    pcre *re;
    struct re_info info;

    PCRE() {
      re = NULL;
    }
    ~PCRE() {
      free_re();
    }
    void free_re() {
      if (re) {
        pcre_free(re);
        re = NULL;
      }
      FREE_INFO(&info);
    }

    static Handle<Value> New(const Arguments& args) {
      HandleScope scope;

      if (!args.IsConstructCall()) {
        return ThrowException(Exception::Error(
            String::New("Use `new` to create instances of this object."))
        );
      }

      PCRE *obj = new PCRE();
      obj->Wrap(args.This());

      if (args.Length() >= 1) {
        if (Buffer::HasInstance(args[0]))
          PCRE::Load(args);
        else if (args[0]->IsString()) {
          Handle<Value> ret = PCRE::Set(args);
          if (ret != Undefined())
            return ret;
        }
      }

      return args.This();
    }

    static Handle<Value> Load(const Arguments& args) {
      HandleScope scope;
      PCRE *obj = ObjectWrap::Unwrap<PCRE>(args.This());

      if (args.Length() < 1) {
        return ThrowException(Exception::TypeError(
            String::New("Missing data argument")));
      }
      if (!Buffer::HasInstance(args[0])) {
        return ThrowException(Exception::TypeError(
            String::New("data argument must be a Buffer")));
      }

      Local<Object> re_obj = args[0]->ToObject();
      size_t len = Buffer::Length(re_obj);
      pcre *re = (pcre*)malloc(len);
      int r;
      struct re_info info;

      memcpy(re, Buffer::Data(re_obj), len);

      r = getCapInfo(re, &info);
      if (r < 0) {
        free(re);
        Local<Object> err_obj =
          Exception::Error(err_fullinfo_symbol)->ToObject();
        err_obj->Set(errcode_symbol, Integer::New(r));
        return ThrowException(err_obj);
      }

      obj->free_re();
      obj->re = re;
      obj->info.caplen = info.caplen;
      obj->info.ovecsize = info.ovecsize;
      obj->info.ovector = info.ovector;
      obj->info.name_map = info.name_map;
      obj->info.extra = info.extra;

      return Undefined();
    }

    static Handle<Value> Save(const Arguments& args) {
      HandleScope scope;
      PCRE *obj = ObjectWrap::Unwrap<PCRE>(args.This());

      if (obj->re) {
        size_t size;
        int r = pcre_fullinfo(obj->re, obj->info.extra, PCRE_INFO_SIZE, &size);
        if (r < 0) {
          Local<Object> err_obj =
            Exception::Error(err_fullinfo_symbol)->ToObject();
          err_obj->Set(errcode_symbol, Integer::New(r));
          return ThrowException(err_obj);
        }
        Buffer *buf = Buffer::New((char*)obj->re, size);
        return scope.Close(buf->handle_);
      } else {
        return ThrowException(
          Exception::Error(String::New("No pattern initialized"))
        );
      }
    }

    static Handle<Value> Set(const Arguments& args) {
      HandleScope scope;
      PCRE *obj = ObjectWrap::Unwrap<PCRE>(args.This());

      if (args.Length() == 0) {
        return ThrowException(
          Exception::Error(String::New("Missing pattern"))
        );
      }

      int options = 0, erroffset, r;
      const char *err;
      struct re_info info;
      String::Utf8Value pat(args[0]);

      if (args.Length() > 1 && args[1]->IsUint32())
        options = args[1]->Uint32Value();

      pcre *re = pcre_compile2(*pat, options, &r, &err, &erroffset, NULL);

      if (re == NULL) {
        Local<Object> err_obj = Exception::Error(String::New(err))->ToObject();
        err_obj->Set(erroffset_symbol, Integer::New(erroffset));
        err_obj->Set(errcode_symbol, Integer::New(r));
        return ThrowException(err_obj);
      }

      r = getCapInfo(re, &info);
      if (r < 0) {
        pcre_free(re);
        Local<Object> err_obj =
          Exception::Error(err_fullinfo_symbol)->ToObject();
        err_obj->Set(errcode_symbol, Integer::New(r));
        return ThrowException(err_obj);
      }

      obj->free_re();
      obj->re = re;
      obj->info.caplen = info.caplen;
      obj->info.ovecsize = info.ovecsize;
      obj->info.ovector = info.ovector;
      obj->info.name_map = info.name_map;
      obj->info.extra = info.extra;

      return Undefined();
    }

    static Handle<Value> Study(const Arguments& args) {
      HandleScope scope;
      PCRE *obj = ObjectWrap::Unwrap<PCRE>(args.This());

      if (obj->re) {
        const char *err = NULL;
        int options = 0;
        if (args.Length() > 0 && args[0]->IsInt32())
          options = args[0]->Int32Value();
        pcre_extra *extra = pcre_study(obj->re, options, &err);
        if (extra) {
          if (obj->info.extra)
            pcre_free_study(obj->info.extra);
          obj->info.extra = extra;
          return True();
        } else if (err) {
          return ThrowException(
            Exception::Error(String::New(err))
          );
        } else
          return False();
      } else {
        return ThrowException(
          Exception::Error(String::New("No pattern initialized"))
        );
      }
    }

    static Handle<Value> Exec_(const Arguments& args, int what = WHAT_EXEC) {
      HandleScope scope;
      pcre *re;
      struct re_info *info = NULL;
      struct re_info tmp_info;
      int r, offset, options = 0, subpos, caplen = 0;
      const char *subject;
      size_t sublen;
      bool isInstance = (args.This()->InternalFieldCount() > 0);

      if (isInstance) {
        // pcre.exec(subject, offset[, options])
        subpos = 0;
        offset = args[1]->Int32Value();
        if (args.Length() > 2 && args[2]->IsInt32())
          options = args[2]->Int32Value();

        PCRE *obj = ObjectWrap::Unwrap<PCRE>(args.This());
        re = obj->re;
        info = &obj->info;
        caplen = info->caplen;
      } else {
        // PCRE.exec(pattern, subject, offset[, options])
        subpos = 1;
        int erroffset;
        const char *err;

        String::Utf8Value pat(args[0]);
        offset = args[2]->Int32Value();
        if (args.Length() > 3 && args[3]->IsInt32())
          options = args[3]->Int32Value();

        re = pcre_compile2(*pat, options, &r, &err, &erroffset, NULL);

        if (re == NULL) {
          Local<Object> err_obj = Exception::Error(String::New(err))->ToObject();
          err_obj->Set(erroffset_symbol, Integer::New(erroffset));
          err_obj->Set(errcode_symbol, Integer::New(r));
          return ThrowException(err_obj);
        }

        // TODO: automatically study pattern if what == WHAT_EXECALL
        //       or custom option to allow this for any what value?
        if (what != WHAT_TEST) {
          tmp_info.extra = NULL;
          r = getCapInfo(re, &tmp_info);
          if (r < 0) {
            pcre_free(re);
            Local<Object> err_obj =
              Exception::Error(err_fullinfo_symbol)->ToObject();
            err_obj->Set(errcode_symbol, Integer::New(r));
            return ThrowException(err_obj);
          }
          info = &tmp_info;
          caplen = info->caplen;
        }
      }

      // this is the only way to get at a string subject's contents long enough
      // to do the matching without making a copy.
      // if the subject is not a string, then oh well...
      String::Utf8Value utfsub(args[subpos]);
      subject = *utfsub;

      if (Buffer::HasInstance(args[subpos])) {
#if NODE_MAJOR_VERSION == 0 && NODE_MINOR_VERSION < 10
        Local<Object> sub_obj = args[subpos]->ToObject();
#else
        Local<Value> sub_obj = args[subpos];
#endif
        subject = Buffer::Data(sub_obj);
        sublen = Buffer::Length(sub_obj);
      } else if (args[subpos]->IsString())
        sublen = strlen(subject);
      else {
        if (!isInstance) {
          pcre_free(re);
          FREE_INFO(info);
        }
        return ThrowException(
          Exception::TypeError(String::New("Invalid subject type"))
        );
      }

      Local<Array> matches;
      Local<Array> match;
      Local<Object> named;
      Local<Integer> lbound, rbound;
      NameMap::iterator name_it;
      pair<NameMap::iterator, NameMap::iterator> name_its;
      Local<Array> name_bounds;
      int arraylen = 2 + caplen, n = 0, i, o;
      bool hasNames = (info ? !info->name_map.empty() : false);

      if (what == WHAT_EXECALL)
        matches = Array::New();

      while (true) {
        r = pcre_exec(re,
                      (info ? info->extra : NULL),
                      subject, sublen, offset, options,
                      (info ? info->ovector : NULL),
                      (info ? info->ovecsize : 0)
        );

        if (r < 0) {
          if (r == PCRE_ERROR_NOMATCH) {
            if (what == WHAT_TEST) {
              if (!isInstance)
                pcre_free(re);
              return False();
            } else if (n == 0) {
              if (!isInstance) {
                pcre_free(re);
                FREE_INFO(info);
              }
              return Null();
            } else {
              if (!isInstance) {
                pcre_free(re);
                FREE_INFO(info);
              }
              return scope.Close(matches);
            }
          } else {
            if (!isInstance) {
              pcre_free(re);
              FREE_INFO(info);
            }
          }
          return scope.Close(Integer::New(r));
        }

        if (what == WHAT_TEST) {
          if (!isInstance)
            pcre_free(re);
          return True();
        } else {
          match = Array::New(arraylen);
          match->Set(0, Integer::New(info->ovector[0]));
          match->Set(1, Integer::New(info->ovector[1]));
          if (!hasNames) {
            for (i = o = 2; i < arraylen; ++i, o += 2) {
              match->Set(i, Integer::New(info->ovector[o]));
              match->Set(i + 1, Integer::New(info->ovector[o + 1]));
            }
          } else {
            named = Object::New();
            for (i = o = 2; i < arraylen; ++i, o += 2) {
              lbound = Integer::New(info->ovector[o]);
              rbound = Integer::New(info->ovector[o + 1]);
              match->Set(i, lbound);
              match->Set(i + 1, rbound);
              name_its = info->name_map.equal_range(i - 1);
              for (name_it = name_its.first;
                   name_it != name_its.second;
                   ++name_it) {
                name_bounds = Array::New(2);
                name_bounds->Set(0, lbound);
                name_bounds->Set(1, rbound);
                named->Set(String::New(name_it->second), name_bounds);
              }
            }
            match->Set(named_symbol, named);
          }

          if (what == WHAT_EXEC) {
            if (!isInstance) {
              pcre_free(re);
              FREE_INFO(info);
            }
            return scope.Close(match);
          } else
            matches->Set(n++, match);
        }

        /*if (info->ovector[0] == info->ovector[1]) {
          if (info->ovector[0] == sublen)
            
        }*/
        offset = info->ovector[1];
      }
    }

    static Handle<Value> Exec(const Arguments& args) {
      return PCRE::Exec_(args, WHAT_EXEC);
    }

    static Handle<Value> ExecAll(const Arguments& args) {
      return PCRE::Exec_(args, WHAT_EXECALL);
    }

    static Handle<Value> Test(const Arguments& args) {
      return PCRE::Exec_(args, WHAT_TEST);
    }

    static Handle<Value> Version(const Arguments& args) {
      HandleScope scope;
      return scope.Close(String::New(pcre_version()));
    }

    static void Initialize(Handle<Object> target) {
      HandleScope scope;

      Local<FunctionTemplate> tpl = FunctionTemplate::New(New);
      Local<String> name = String::NewSymbol("PCRE");

      constructor = Persistent<FunctionTemplate>::New(tpl);
      constructor->InstanceTemplate()->SetInternalFieldCount(1);
      constructor->SetClassName(name);

      NODE_SET_PROTOTYPE_METHOD(constructor, "load", Load);
      NODE_SET_PROTOTYPE_METHOD(constructor, "save", Save);
      NODE_SET_PROTOTYPE_METHOD(constructor, "set", Set);
      NODE_SET_PROTOTYPE_METHOD(constructor, "study", Study);
      NODE_SET_PROTOTYPE_METHOD(constructor, "exec", Exec);
      NODE_SET_PROTOTYPE_METHOD(constructor, "execAll", ExecAll);
      NODE_SET_PROTOTYPE_METHOD(constructor, "test", Test);

      NODE_SET_METHOD(constructor->GetFunction(), "version", PCRE::Version);
      NODE_SET_METHOD(constructor->GetFunction(), "exec", PCRE::Exec);
      NODE_SET_METHOD(constructor->GetFunction(), "execAll", PCRE::ExecAll);
      NODE_SET_METHOD(constructor->GetFunction(), "test", PCRE::Test);

      erroffset_symbol = NODE_PSYMBOL("offset");
      errcode_symbol = NODE_PSYMBOL("code");
      named_symbol = NODE_PSYMBOL("named");
      err_fullinfo_symbol = NODE_PSYMBOL("pcre_fullinfo failure");

      target->Set(name, constructor->GetFunction());
    }
};

extern "C" {
  void init(Handle<Object> target) {
    HandleScope scope;
    PCRE::Initialize(target);
  }

  NODE_MODULE(pcre, init);
}

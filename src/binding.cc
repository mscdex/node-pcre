#include <node.h>
#include <node_buffer.h>
#include <string.h>
#ifdef __APPLE__
# include <tr1/unordered_map>
  using namespace std::tr1;
#else
# include <unordered_map>
#endif

#include "pcre.h"

#define WHAT_EXEC 0
#define WHAT_EXECALL 1
#define WHAT_TEST 2

#define DEFAULT_JIT_STACK_START 1
#define DEFAULT_JIT_STACK_MAX 32 * 1024

#define EXEC_ONLY_OPTIONS (PCRE_ANCHORED            \
                           | PCRE_NOTBOL            \
                           | PCRE_NOTEOL            \
                           | PCRE_NOTEMPTY          \
                           | PCRE_NO_UTF8_CHECK     \
                           | PCRE_PARTIAL           \
                           | PCRE_NEWLINE_CR        \
                           | PCRE_NEWLINE_LF        \
                           | PCRE_NEWLINE_CRLF      \
                           | PCRE_NEWLINE_ANY       \
                           | PCRE_NEWLINE_ANYCRLF   \
                           | PCRE_BSR_ANYCRLF       \
                           | PCRE_BSR_UNICODE       \
                           | PCRE_NO_START_OPTIMIZE \
                           | PCRE_PARTIAL_HARD      \
                           | PCRE_NOTEMPTY_ATSTART)


#define FREE_INFO(info) {                           \
          if (info) {                               \
            if ((info)->ovector)                    \
              free((info)->ovector);                \
            (info)->ovector = NULL;                 \
            (info)->caplen = (info)->ovecsize = 0;  \
            (info)->jit = false;                    \
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
              extra(NULL),
              jit(false),
              jit_stack(NULL) {}

  int caplen;
  int ovecsize;
  int *ovector;

  NameMap name_map;

  pcre_extra *extra;
  bool jit;
  pcre_jit_stack *jit_stack;
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
#if defined(_MSC_VER) || defined(__APPLE__)
        info->name_map.rehash(ceil(name_count/info->name_map.max_load_factor()));
#else
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
      if (info.jit_stack)
        pcre_jit_stack_free(info.jit_stack);
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

#if NODE_MAJOR_VERSION == 0 && NODE_MINOR_VERSION < 10
      Local<Object> re_obj = args[0]->ToObject();
#else
      Local<Value> re_obj = args[0];
#endif
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
          if ((options & (PCRE_STUDY_JIT_COMPILE
                         | PCRE_STUDY_JIT_PARTIAL_HARD_COMPILE
                         | PCRE_STUDY_JIT_PARTIAL_SOFT_COMPILE)) > 0) {
            int start_size = DEFAULT_JIT_STACK_START,
                max_size = DEFAULT_JIT_STACK_MAX;

            obj->info.jit = true;

            if (args.Length() == 3 && args[1]->IsInt32() && args[2]->IsInt32()) {
              start_size = args[1]->Int32Value();
              max_size = args[2]->Int32Value();
            }

            if (start_size > 0 && max_size >= start_size) {
              pcre_jit_stack *s = pcre_jit_stack_alloc(start_size, max_size);
              if (obj->info.jit_stack)
                pcre_jit_stack_free(obj->info.jit_stack);
              obj->info.jit_stack = s;
              pcre_assign_jit_stack(extra, NULL, s);
            }
          } else
            obj->info.jit = false;
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

        options &= EXEC_ONLY_OPTIONS;

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
      // to do the matching without making a copy due to scoping destructing the
      // Utf8Value.
      // if the subject is not a string, then hopefully v8 did not spend a lot
      // of resources in finding that out...
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
        sublen = args[subpos]->ToString()->Utf8Length();
      else {
        if (!isInstance) {
          pcre_free(re);
          FREE_INFO(info);
        }
        return ThrowException(
          Exception::TypeError(String::New("Invalid subject type"))
        );
      }

      int arraylen = 2 + caplen * 2, n = 0, i, o;
      Local<Array> matches;
      Local<Array> match;

      Local<Object> named;
      Local<Integer> lbound, rbound;
      NameMap::iterator name_it;
      pair<NameMap::iterator, NameMap::iterator> name_its;
      Local<Array> name_bounds;
      bool hasNames = (info ? !info->name_map.empty() : false);

      bool crlf_is_newline = false, isUtf8 = false;
      int cur_options = options,
          tmp_options = options | PCRE_NOTEMPTY_ATSTART | PCRE_ANCHORED;
      if (what == WHAT_EXECALL) {
        matches = Array::New();
        int re_opts;
        r = pcre_fullinfo(re,
                          (info ? info->extra : NULL),
                          PCRE_INFO_OPTIONS,
                          &re_opts);
        if (r < 0) {
          if (!isInstance) {
            pcre_free(re);
            FREE_INFO(info);
          }
          return ThrowException(Exception::TypeError(err_fullinfo_symbol));
        }
        options |= (re_opts & EXEC_ONLY_OPTIONS);
      // If we want to continue to search for additional matches in the subject
      // string, in a similar way to the /g option in Perl, doing so turns out
      // to be trickier than you might think because of the possibility of
      // matching an empty string. What happens is as follows:
      //
      // If the previous match was NOT for an empty string, we can just start
      // the next match at the end of the previous one.
      //
      // If the previous match WAS for an empty string, we can't do that, as it
      // would lead to an infinite loop. Instead, a special call of pcre_exec()
      // is made with the PCRE_NOTEMPTY_ATSTART and PCRE_ANCHORED flags set.
      // The first of these tells PCRE that an empty string at the start of the
      // subject is not a valid match; other possibilities must be tried. The
      // second flag restricts PCRE to one match attempt at the initial string
      // position. If this match succeeds, an alternative to the empty string
      // match has been found, and we can print it and proceed round the loop,
      // advancing by the length of whatever was found. If this match does not
      // succeed, we still stay in the loop, advancing by just one character.
      // In UTF-8 mode, which can be set by (*UTF8) in the pattern, this may be
      // more than one byte.
      //
      // However, there is a complication concerned with newlines. When the
      // newline convention is such that CRLF is a valid newline, we must
      // advance by two characters rather than one. The newline convention can
      // be set in the regex by (*CR), etc.; if not, we must find the default.
        if (options == 0) {
          int def_newline;
          r = pcre_config(PCRE_CONFIG_NEWLINE, &def_newline);
          if (r < 0) {
            if (!isInstance) {
              pcre_free(re);
              FREE_INFO(info);
            }
            return ThrowException(
              Exception::TypeError(String::New("pcre_config failure"))
            );
          }
          crlf_is_newline = (def_newline == (13<<8 | 10) || def_newline == -2
                             || def_newline == -1);
        } else {
          crlf_is_newline = ((options & (PCRE_NEWLINE_ANY | PCRE_NEWLINE_CRLF
                                         | PCRE_NEWLINE_ANYCRLF)) > 0);
        }
        isUtf8 = ((options & PCRE_UTF8) > 0);
      }

      while (true) {
        if (info && info->jit) {
          // fast path that bypasses some checks that pcre_exec would otherwise
          // do before executing the JIT compiled code
          r = pcre_jit_exec(re,
                            info->extra,
                            subject,
                            sublen,
                            offset,
                            cur_options,
                            (info ? info->ovector : NULL),
                            (info ? info->ovecsize : 0),
                            info->jit_stack
          );
        } else {
          r = pcre_exec(re,
                        (info ? info->extra : NULL),
                        subject,
                        sublen,
                        offset,
                        cur_options,
                        (info ? info->ovector : NULL),
                        (info ? info->ovecsize : 0)
          );
        }

        if (r < 0) {
          if (r == PCRE_ERROR_NOMATCH) {
            if (what == WHAT_EXECALL && n > 0) {
              if (cur_options == options)
                goto done;
              ++info->ovector[1];
              if (crlf_is_newline && info->ovector[1] < (sublen - 1)
                  && subject[offset] == '\r' && subject[offset + 1] == '\n')
                ++info->ovector[1];
              else if (isUtf8) {
                while (info->ovector[1] < sublen) {
                  if ((subject[info->ovector[1]] & 0xC0) != 0x80)
                    break;
                  ++info->ovector[1];
                }
              }
              goto next;
            }
            goto done;
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
            for (i = 2; i < arraylen; i += 2) {
              match->Set(i, Integer::New(info->ovector[i]));
              match->Set(i + 1, Integer::New(info->ovector[i + 1]));
            }
          } else {
            named = Object::New();
            for (i = o = 2; o < arraylen; ++i, o += 2) {
              lbound = Integer::New(info->ovector[o]);
              rbound = Integer::New(info->ovector[o + 1]);
              match->Set(o, lbound);
              match->Set(o + 1, rbound);
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

        next:
        offset = info->ovector[1];

        // If the previous match was for an empty string, we are finished if we
        // are at the end of the subject. Otherwise, arrange to run another
        // match at the same point to see if a non-empty match can be found.
        if (info->ovector[0] == info->ovector[1]) {
          if (info->ovector[0] == sublen)
            goto done;
          else
            cur_options = tmp_options;
        } else
          cur_options = options;
      }

      done:
      if (what == WHAT_TEST) {
        if (!isInstance)
          pcre_free(re);
        return False();
      } else if (what == WHAT_EXEC || n == 0) {
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

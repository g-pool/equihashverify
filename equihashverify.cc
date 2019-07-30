#include <nan.h>
#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <sodium.h>
#include <vector>

#include "crypto/equihashR.h"
#include "beam/core/difficulty.h"
#include "beam/core/uintBig.h"

using namespace v8;

bool verifyEH(const char *hdr, const char *nonceBuffer, const std::vector<unsigned char> &soln, unsigned int n = 150, unsigned int k = 5, unsigned int r = 0){

  eh_HashState state;
  EhRInitialiseState(n, k, r, state);
  blake2b_update(&state, (const unsigned char *)hdr, 32);
  blake2b_update(&state, (const unsigned char *)nonceBuffer, 8);

  bool isValid;
  if (n == 150 && k == 5 && r == 0) {
    isValid = BeamHashI.IsValidSolution(state, soln);
  } else if (n == 150 && k == 5 && r == 3) {
    isValid = BeamHashII.IsValidSolution(state, soln);
  } else {
    throw std::invalid_argument("Unsupported Equihash parameters");
  }
  return isValid;
}

bool checkDiff( const std::vector<unsigned char> &vecSolution, unsigned int diff){

    beam::Difficulty powDiff = beam::Difficulty(diff);
    beam::uintBig_t<32> hv;
    crypto_hash_sha256(hv.m_pData, vecSolution.data(), vecSolution.size());
    bool result = powDiff.IsTargetReached(hv);

    return result;
}

void Verify(const v8::FunctionCallbackInfo<Value>& args) {
    Isolate* isolate = Isolate::GetCurrent();
    HandleScope scope(isolate);

    unsigned int n = 150;
    unsigned int k = 5;
    unsigned int r = 0;
    unsigned int netdiff = 0;
    unsigned int sharediff = 0;

    if (args.Length() < 5) {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
    return;
    }

    Local<Object> header = args[0]->ToObject();
    Local<Object> nonce = args[1]->ToObject();
    Local<Object> solution = args[2]->ToObject();

    netdiff = args[3]->Uint32Value();
    sharediff = args[4]->Uint32Value();

    if (args.Length() == 6) {
    r = args[5]->Uint32Value();
    }

    if(!node::Buffer::HasInstance(header) || !node::Buffer::HasInstance(solution) || !node::Buffer::HasInstance(nonce) ) {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Arguments should be buffer objects.")));
    return;
    }

    const char *hdr = node::Buffer::Data(header);
    const char *nonceBuffer = node::Buffer::Data(nonce);
    if(node::Buffer::Length(header) != 32) {
      //invalid hdr length
      args.GetReturnValue().Set(false);
      return;
    }
    const char *soln = node::Buffer::Data(solution);

    std::vector<unsigned char> vecSolution(soln, soln + node::Buffer::Length(solution));
    bool isValidSolution = verifyEH(hdr, nonceBuffer, vecSolution, n, k, r);

    int retval  = 0;

    if ( isValidSolution &&  checkDiff(vecSolution, netdiff) ){
        retval = 3; //Valid BLOCK
    }
    else if ( isValidSolution &&  checkDiff(vecSolution, sharediff) ){
        retval = 2; //Valid Share
    }
    else if ( isValidSolution ){
        retval = 1; //Low diff
    }

    args.GetReturnValue().Set(retval);

}

void TargetReached(const v8::FunctionCallbackInfo<Value> &args)
{
  Isolate *isolate = Isolate::GetCurrent();
  HandleScope scope(isolate);
  if (args.Length() < 2)
  {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Wrong number of arguments")));
    return;
  }
  unsigned int diff = 0;

  Local<Object> solution = args[0]->ToObject();
  if (!node::Buffer::HasInstance(solution))
  {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Argument should be buffer objects.")));
    return;
  }
  diff = args[1]->Uint32Value();

  const char *soln = node::Buffer::Data(solution);
  std::vector<unsigned char> vecSolution(soln, soln + node::Buffer::Length(solution));

  beam::Difficulty powDiff = beam::Difficulty(diff);
  beam::uintBig_t<32> hv;
  crypto_hash_sha256(hv.m_pData, vecSolution.data(), vecSolution.size());
  bool result = powDiff.IsTargetReached(hv);
  args.GetReturnValue().Set(result);
}

void Init(Handle<Object> exports)
{
  NODE_SET_METHOD(exports, "verify", Verify);
  NODE_SET_METHOD(exports, "targetReached", TargetReached);
}

NODE_MODULE(equihashverify, Init)

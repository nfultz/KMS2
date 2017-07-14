
#include <aws/core/Aws.h>
#include <aws/core/auth/AWSCredentialsProviderChain.h>
#include <aws/core/client/ClientConfiguration.h>
#include <aws/core/utils/crypto/ContentCryptoMaterial.h>
#include <aws/kms/KMSClient.h>
#include <aws/kms/model/EncryptRequest.h>
#include <aws/kms/model/EncryptResult.h>
#include <aws/kms/model/DecryptRequest.h>
#include <aws/kms/model/DecryptResult.h>
#include <aws/kms/model/GenerateDataKeyRequest.h>
#include <aws/kms/model/GenerateDataKeyResult.h>
#include <aws/core/utils/Outcome.h>
#include <Rcpp.h>

using namespace Rcpp;
using namespace Aws::Auth;
using namespace Aws::Http;
using namespace Aws::Client;
using namespace Aws::KMS;
using namespace Aws::KMS::Model;
using namespace Aws::Utils;

static Aws::KMS::KMSClient *client;

// [[Rcpp::export]]
RawVector rcpp_encrypt(CharacterVector key, RawVector text) {
  Aws::String aws_key(key(0));

  unsigned char buffer[4*1024];
  memcpy(buffer, text.begin(), text.size());
  
  
  Aws::Utils::ByteBuffer aws_bb(buffer, text.size());


  Aws::SDKOptions options;
  Aws::InitAPI(options);
  Rcout << ("Built InitAPI");
  
  Aws::Client::ClientConfiguration config;
  config.region = Aws::Region::US_WEST_2;
  client = new KMSClient(config);
  
  Rcout << ("Built client\n");
  
  
  EncryptRequest request;
  request.SetPlaintext(aws_bb);
  request.SetKeyId(aws_key);
  Rcout << "Request Built\n";  
  
    
  EncryptOutcome outcome = client->Encrypt(request);
  Rcout << ("encrpyt()");
  
  if (!outcome.IsSuccess())
  {
    Rcout << ("encrpyt() not successfull");
    
    // AWS_LOGSTREAM_ERROR(ALLOCATION_TAG, "KMS encryption call not successful: "
    //                       << outcome.GetError().GetExceptionName() << " : " << outcome.GetError().GetMessage());
    //return without changing the encrypted content encryption key
    RawVector out(1);
    return out;
  }
  
  Aws::KMS::Model::EncryptResult result = outcome.GetResult();
  Rcout << ("got result");
  
  auto resultblob = result.GetCiphertextBlob();
  RawVector ret(resultblob.GetLength());
  for(int i = 0; i < resultblob.GetLength(); i++){
    // Rcout << i << ":" << resultblob.GetItem(i) << "\n";
    ret(i) = resultblob.GetItem(i);
  }
  
  return ret;
}

// [[Rcpp::export]]
RawVector rcpp_decrypt(RawVector text) {

  unsigned char buffer[4*1024];
  memcpy(buffer, text.begin(), text.size());
  
  
  Aws::Utils::ByteBuffer aws_bb(buffer, text.size());
  
  static const char* ALLOCATION_TAG = "KMS2";
  
  
  
  Aws::SDKOptions options;
  Aws::InitAPI(options);
  Rcout << ("Built InitAPI");
  
  Aws::Client::ClientConfiguration config;
  config.region = Aws::Region::US_WEST_2;
  client = new KMSClient(config);
  
  Rcout << ("Built client\n");
  
  
  DecryptRequest request;
  request.SetCiphertextBlob(aws_bb);
  Rcout << "Request Built\n";  
  
  
  DecryptOutcome decoutcome = client->Decrypt(request);
  Rcout << ("decrypt()\n");
  
  if (!decoutcome.IsSuccess())
  {
    auto err = decoutcome.GetError();
    Rcout << ("decrypt() not successfull\n") <<  err.GetExceptionName() << " :\n  " << err.GetMessage();
    
    RawVector out(1);
    
    return out;
  }
  
  Aws::KMS::Model::DecryptResult result = decoutcome.GetResult();
  Rcout << ("got result\n");
  
  auto resultblob = result.GetPlaintext();
  Rcout << ("got blob\n");
  
  RawVector ret(resultblob.GetLength());
  for(int i = 0; i < resultblob.GetLength(); i++){
     // Rcout << i << ":" << resultblob.GetItem(i) << "\n";
     ret(i) = resultblob.GetItem(i);
  }
  
  return ret;
}

// [[Rcpp::export]]
Rcpp::List rcpp_generate(CharacterVector key, int bytes) {
  Aws::String aws_key(key(0));
  
  
  Aws::SDKOptions options;
  Aws::InitAPI(options);
  Rcout << ("Built InitAPI");
  
  Aws::Client::ClientConfiguration config;
  config.region = Aws::Region::US_WEST_2;
  client = new KMSClient(config);
  
  Rcout << ("Built client\n");
  
  
  GenerateDataKeyRequest request;
  request.SetKeyId(aws_key);
  Rcout << "Request Built\n";  
  
  
  GenerateDataKeyOutcome genoutcome = client->GenerateDataKey(request);
  Rcout << ("generate()\n");
  
  if (!genoutcome.IsSuccess())
  {
    auto err = genoutcome.GetError();
    Rcout << ("generate() not successfull\n") <<  err.GetExceptionName() << " :\n  " << err.GetMessage();
    
    Rcpp::List out(1);
    
    return out;
  }
  
  Aws::KMS::Model::GenerateDataKeyResult result = genoutcome.GetResult();
  Rcout << ("got result\n");
  
  auto resultblob = result.GetPlaintext();
  Rcout << ("got blob\n");
  
  RawVector plain(resultblob.GetLength());
  for(int i = 0; i < resultblob.GetLength(); i++){
    // Rcout << i << ":" << resultblob.GetItem(i) << "\n";
    plain(i) = resultblob.GetItem(i);
  }

  resultblob = result.GetCiphertextBlob();
  RawVector cipher(resultblob.GetLength());
  for(int i = 0; i < resultblob.GetLength(); i++){
    // Rcout << i << ":" << resultblob.GetItem(i) << "\n";
    cipher(i) = resultblob.GetItem(i);
  }
  
  
    
  return  Rcpp::List::create(Rcpp::Named("plain") = plain,
                                   Rcpp::Named("cipher") = cipher,
                                   Rcpp::Named("key") = key);;
}

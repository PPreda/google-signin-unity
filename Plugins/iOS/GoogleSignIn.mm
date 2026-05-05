/**
 * Copyright 2017 Google Inc.
 *
 * Licensed under the Apache License, Version 2.0
 */
#import "GoogleSignIn.h"

#import <GoogleSignIn/GoogleSignIn.h>
#import <UnityAppController.h>
#import "UnityInterface.h"

#import <memory>

static const int kStatusCodeSuccessCached = -1;
static const int kStatusCodeSuccess = 0;
static const int kStatusCodeApiNotConnected = 1;
static const int kStatusCodeCanceled = 2;
static const int kStatusCodeInterrupted = 3;
static const int kStatusCodeInvalidAccount = 4;
static const int kStatusCodeTimeout = 5;
static const int kStatusCodeDeveloperError = 6;
static const int kStatusCodeInternalError = 7;
static const int kStatusCodeNetworkError = 8;
static const int kStatusCodeError = 9;

void UnpauseUnityPlayer() {
  dispatch_async(dispatch_get_main_queue(), ^{
    if (UnityIsPaused() > 0) {
      UnityPause(0);
    }
  });
}

struct SignInResult {
  int result_code;
  bool finished;
};

std::unique_ptr<SignInResult> currentResult_;
NSRecursiveLock *resultLock = [NSRecursiveLock alloc];

static NSString *lastServerAuthCode = nil;

@implementation GoogleSignInHandler

GIDConfiguration *signInConfiguration = nil;
NSString *loginHint = nil;
NSMutableArray *additionalScopes = nil;

+ (GoogleSignInHandler *)sharedInstance {
  static dispatch_once_t once;
  static GoogleSignInHandler *sharedInstance;
  dispatch_once(&once, ^{
    sharedInstance = [self alloc];
  });
  return sharedInstance;
}

- (void)finishSignInWithUser:(GIDGoogleUser *)user
              serverAuthCode:(NSString *)serverAuthCode
                        error:(NSError *)error {
  if (error == nil && user != nil) {
    if (serverAuthCode != nil) {
      lastServerAuthCode = [serverAuthCode copy];
    }

    if (currentResult_) {
      currentResult_->result_code = kStatusCodeSuccess;
      currentResult_->finished = true;
    } else {
      NSLog(@"No currentResult to set status on!");
    }

    NSLog(@"GoogleSignIn: SUCCESS");
    UnpauseUnityPlayer();
    return;
  }

  NSLog(@"GoogleSignIn error: %@", error.localizedDescription);

  if (currentResult_) {
    switch (error.code) {
      case kGIDSignInErrorCodeUnknown:
        currentResult_->result_code = kStatusCodeError;
        break;

      case kGIDSignInErrorCodeKeychain:
        currentResult_->result_code = kStatusCodeInternalError;
        break;

      case kGIDSignInErrorCodeHasNoAuthInKeychain:
        currentResult_->result_code = kStatusCodeError;
        break;

      case kGIDSignInErrorCodeCanceled:
        currentResult_->result_code = kStatusCodeCanceled;
        break;

      default:
        NSLog(@"Unmapped error code: %ld, returning Error",
              static_cast<long>(error.code));
        currentResult_->result_code = kStatusCodeError;
        break;
    }

    currentResult_->finished = true;
    UnpauseUnityPlayer();
  } else {
    NSLog(@"No currentResult to set status on!");
  }
}

- (void)finishDisconnectWithError:(NSError *)error {
  if (error == nil) {
    NSLog(@"GoogleSignIn disconnect: SUCCESS");
  } else {
    NSLog(@"GoogleSignIn disconnect error: %@", error);
  }
}

@end

extern "C" {

void *GoogleSignIn_Create(void *data) { return NULL; }

void GoogleSignIn_EnableDebugLogging(void *unused, bool flag) {
  if (flag) {
    NSLog(@"GoogleSignIn: No optional logging available on iOS");
  }
}

bool GoogleSignIn_Configure(void *unused, bool useGameSignIn,
                            const char *webClientId, bool requestAuthCode,
                            bool forceTokenRefresh, bool requestEmail,
                            bool requestIdToken, bool hidePopups,
                            const char **additionalScopes, int scopeCount,
                            const char *accountName) {
  NSString *path = [[NSBundle mainBundle] pathForResource:@"GoogleService-Info" ofType:@"plist"];
  NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:path];
  NSString *clientId = [dict objectForKey:@"CLIENT_ID"];

  if (clientId == nil) {
    NSLog(@"GoogleSignIn: GoogleService-Info.plist CLIENT_ID is missing.");
    return false;
  }

  GIDConfiguration *config = nil;

  if (webClientId && strlen(webClientId) > 0) {
    config = [[GIDConfiguration alloc] initWithClientID:clientId
                                         serverClientID:[NSString stringWithUTF8String:webClientId]];
  } else {
    config = [[GIDConfiguration alloc] initWithClientID:clientId];
  }

  [GoogleSignInHandler sharedInstance]->signInConfiguration = config;
  [GIDSignIn sharedInstance].configuration = config;

  int scopeSize = scopeCount;
  if (scopeSize) {
    NSMutableArray *tmpary = [[NSMutableArray alloc] initWithCapacity:scopeSize];
    for (int i = 0; i < scopeCount; i++) {
      [tmpary addObject:[NSString stringWithUTF8String:additionalScopes[i]]];
    }
    [GoogleSignInHandler sharedInstance]->additionalScopes = tmpary;
  } else {
    [GoogleSignInHandler sharedInstance]->additionalScopes = nil;
  }

  if (accountName && strlen(accountName) > 0) {
    [GoogleSignInHandler sharedInstance]->loginHint = [NSString stringWithUTF8String:accountName];
  } else {
    [GoogleSignInHandler sharedInstance]->loginHint = nil;
  }

  return !useGameSignIn;
}

static SignInResult *startSignIn() {
  bool busy = false;

  [resultLock lock];
  if (!currentResult_ || currentResult_->finished) {
    currentResult_.reset(new SignInResult());
    currentResult_->result_code = 0;
    currentResult_->finished = false;
  } else {
    busy = true;
  }
  [resultLock unlock];

  if (busy) {
    NSLog(@"ERROR: There is already a pending sign-in operation.");
    return new SignInResult{.result_code = kStatusCodeDeveloperError,
                            .finished = true};
  }

  return nullptr;
}

void *GoogleSignIn_SignIn() {
  SignInResult *result = startSignIn();

  if (!result) {
    GIDSignIn *signIn = [GIDSignIn sharedInstance];
    signIn.configuration = [GoogleSignInHandler sharedInstance]->signInConfiguration;

    UnityPause(true);

    [signIn signInWithPresentingViewController:UnityGetGLViewController()
                                          hint:[GoogleSignInHandler sharedInstance]->loginHint
                              additionalScopes:[GoogleSignInHandler sharedInstance]->additionalScopes
                                    completion:^(GIDSignInResult *signInResult, NSError *error) {
      [[GoogleSignInHandler sharedInstance] finishSignInWithUser:signInResult.user
                                                  serverAuthCode:signInResult.serverAuthCode
                                                           error:error];
    }];

    result = currentResult_.get();
  }

  return result;
}

void *GoogleSignIn_SignInSilently() {
  SignInResult *result = startSignIn();

  if (!result) {
    GIDSignIn *signIn = [GIDSignIn sharedInstance];
    signIn.configuration = [GoogleSignInHandler sharedInstance]->signInConfiguration;

    [signIn restorePreviousSignInWithCompletion:^(GIDGoogleUser *user, NSError *error) {
      [[GoogleSignInHandler sharedInstance] finishSignInWithUser:user
                                                  serverAuthCode:nil
                                                           error:error];
    }];

    result = currentResult_.get();
  }

  return result;
}

void GoogleSignIn_Signout() {
  GIDSignIn *signIn = [GIDSignIn sharedInstance];
  [signIn signOut];
  lastServerAuthCode = nil;
}

void GoogleSignIn_Disconnect() {
  GIDSignIn *signIn = [GIDSignIn sharedInstance];

  [signIn disconnectWithCompletion:^(NSError *error) {
    [[GoogleSignInHandler sharedInstance] finishDisconnectWithError:error];
  }];

  lastServerAuthCode = nil;
}

bool GoogleSignIn_Pending(SignInResult *result) {
  volatile bool ret;

  [resultLock lock];
  ret = !result->finished;
  [resultLock unlock];

  return ret;
}

GIDGoogleUser *GoogleSignIn_Result(SignInResult *result) {
  if (result && result->finished) {
    GIDGoogleUser *guser = [GIDSignIn sharedInstance].currentUser;
    return guser;
  }

  return nullptr;
}

int GoogleSignIn_Status(SignInResult *result) {
  if (result) {
    return result->result_code;
  }

  return kStatusCodeDeveloperError;
}

void GoogleSignIn_DisposeFuture(SignInResult *result) {
  if (result == currentResult_.get()) {
    currentResult_.reset(nullptr);
  } else {
    delete result;
  }
}

static size_t CopyNSString(NSString *src, char *dest, size_t len) {
  if (dest && src && len) {
    const char *string = [src UTF8String];
    strncpy(dest, string, len);
    return len;
  }

  return src ? src.length + 1 : 0;
}

size_t GoogleSignIn_GetServerAuthCode(GIDGoogleUser *guser, char *buf,
                                      size_t len) {
  return CopyNSString(lastServerAuthCode, buf, len);
}

size_t GoogleSignIn_GetDisplayName(GIDGoogleUser *guser, char *buf,
                                   size_t len) {
  NSString *val = [guser.profile name];
  return CopyNSString(val, buf, len);
}

size_t GoogleSignIn_GetEmail(GIDGoogleUser *guser, char *buf, size_t len) {
  NSString *val = [guser.profile email];
  return CopyNSString(val, buf, len);
}

size_t GoogleSignIn_GetFamilyName(GIDGoogleUser *guser, char *buf, size_t len) {
  NSString *val = [guser.profile familyName];
  return CopyNSString(val, buf, len);
}

size_t GoogleSignIn_GetGivenName(GIDGoogleUser *guser, char *buf, size_t len) {
  NSString *val = [guser.profile givenName];
  return CopyNSString(val, buf, len);
}

size_t GoogleSignIn_GetIdToken(GIDGoogleUser *guser, char *buf, size_t len) {
  NSString *val = guser.idToken ? guser.idToken.tokenString : nil;
  return CopyNSString(val, buf, len);
}

size_t GoogleSignIn_GetImageUrl(GIDGoogleUser *guser, char *buf, size_t len) {
  NSURL *url = [guser.profile imageURLWithDimension:128];
  NSString *val = url ? [url absoluteString] : nil;
  return CopyNSString(val, buf, len);
}

size_t GoogleSignIn_GetUserId(GIDGoogleUser *guser, char *buf, size_t len) {
  NSString *val = [guser userID];
  return CopyNSString(val, buf, len);
}

} // extern "C"

import AuthenticationServices

@objc(Passkey)
class Passkey: NSObject {
  var passKeyDelegate: PasskeyDelegate?;

  @objc(register:withChallenge:withDisplayName:withUserId:withSecurityKey:withLargeBlobSupport:withResolver:withRejecter:)
  func register(_ identifier: String, challenge: String, displayName: String, userId: String, securityKey: Bool, largeBlobSupport: String, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {
    // Convert challenge and userId to correct type
    guard let challengeData: Data = Data(base64Encoded: challenge) else {
      reject(PassKeyError.invalidChallenge.rawValue, PassKeyError.invalidChallenge.rawValue, nil);
      return;
    }
    let userIdData: Data = RCTConvert.nsData(userId);

    // Check if Passkeys are supported on this OS version
    if #available(iOS 15.0, *) {
      let authController: ASAuthorizationController;

      // Check if registration should proceed with a security key
      if (securityKey) {
        // Create a new registration request with security key
        let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: identifier);
        let authRequest = securityKeyProvider.createCredentialRegistrationRequest(challenge: challengeData, displayName: displayName, name: displayName, userID: userIdData)
        authRequest.credentialParameters = [ ASAuthorizationPublicKeyCredentialParameters(algorithm: ASCOSEAlgorithmIdentifier.ES256) ];
        authController = ASAuthorizationController(authorizationRequests: [authRequest]);
      } else {
        // Create a new registration request without security key
        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: identifier);
        let authRequest = platformProvider.createCredentialRegistrationRequest(challenge: challengeData, name: displayName, userID: userIdData);

        if #available(iOS 17.0, *) {
            if (largeBlobSupport != ""){
                let largeBlobRegistrationInput: ASAuthorizationPublicKeyCredentialLargeBlobRegistrationInput
                // Determine whether Large Blob support is preferred or required
                if largeBlobSupport == "required" {
                    largeBlobRegistrationInput = .supportRequired
                } else {
                    largeBlobRegistrationInput = .supportPreferred
                }
                // let largeBlobWriteInput = ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput.write(largeBlobData)
                authRequest.largeBlob = largeBlobRegistrationInput
            }
        }

        authController = ASAuthorizationController(authorizationRequests: [authRequest]);
      }

      // Set up a PasskeyDelegate instance with a callback function
      self.passKeyDelegate = PasskeyDelegate { error, result in
        // Check if authorization process returned an error and throw if thats the case
        if (error != nil) {
          let passkeyError = self.handleErrorCode(error: error!);
          reject(passkeyError.rawValue, passkeyError.rawValue, nil);
          return;
        }

        // Check if the result object contains a valid registration result
        if let registrationResult = result?.registrationResult {
          // Return a NSDictionary instance with the received authorization data
          let authResponse: NSDictionary = [
            "rawAttestationObject": registrationResult.rawAttestationObject.base64EncodedString(),
            "rawClientDataJSON": registrationResult.rawClientDataJSON.base64EncodedString(),
            "largeBlobSupported": registrationResult.largeBlobSupported,
          ];

          let authResult: NSDictionary = [
            "credentialID": registrationResult.credentialID.base64EncodedString(),
            "response": authResponse
          ]

          // // Check if the largeBlobOutput is available
          //   if #available(iOS 17.0, *), let largeBlobOutput = registrationResult.largeBlobSupported {
          //   authResult["largeBlobSupported"] = largeBlobOutput
          // }

          resolve(authResult);
        } else {
          // If result didn't contain a valid registration result throw an error
          reject(PassKeyError.requestFailed.rawValue, PassKeyError.requestFailed.rawValue, nil);
        }
      }

      if let passKeyDelegate = self.passKeyDelegate {
        // Perform the authorization request
        passKeyDelegate.performAuthForController(controller: authController);
      }
    } else {
      // If Passkeys are not supported throw an error
      reject(PassKeyError.notSupported.rawValue, PassKeyError.notSupported.rawValue, nil);
    }
  }

  @objc(authenticate:withChallenge:withSecurityKey:withLargeBlob:withResolver:withRejecter:)
  func authenticate(_ identifier: String, challenge: String, securityKey: Bool, largeBlob: NSDictionary, resolve: @escaping RCTPromiseResolveBlock, reject: @escaping RCTPromiseRejectBlock) -> Void {

    // Convert challenge to correct type
    guard let challengeData: Data = Data(base64Encoded: challenge) else {
      reject(PassKeyError.invalidChallenge.rawValue, PassKeyError.invalidChallenge.rawValue, nil);
      return;
    }

    // Check if Passkeys are supported on this OS version
    if #available(iOS 15.0, *) {
      let authController: ASAuthorizationController;

      // Check if authentication should proceed with a security key
      if (securityKey) {
        // Create a new assertion request with security key
        let securityKeyProvider = ASAuthorizationSecurityKeyPublicKeyCredentialProvider(relyingPartyIdentifier: identifier);
        let authRequest = securityKeyProvider.createCredentialAssertionRequest(challenge: challengeData);
        authController = ASAuthorizationController(authorizationRequests: [authRequest]);
      } else {
        // Create a new assertion request without security key
        let platformProvider = ASAuthorizationPlatformPublicKeyCredentialProvider(relyingPartyIdentifier: identifier);
        let authRequest = platformProvider.createCredentialAssertionRequest(challenge: challengeData);

      print(largeBlob)

      if #available(iOS 17.0, *) {
          if let writeBlobBase64 = largeBlob["write"] as? String {
              // Convert base64 String to Data
              if let writeBlobData = Data(base64Encoded: writeBlobBase64) {
                  let largeBlobWriteInput = ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput.write(writeBlobData)
                  authRequest.largeBlob = largeBlobWriteInput
              } else {
                  // Handle error: Base64 string is not valid or could not be converted to Data
                  reject(PassKeyError.requestFailed.rawValue, PassKeyError.requestFailed.rawValue, nil);
                  return
              }
          } else if let readBlob = largeBlob["read"] as? Bool, readBlob == true {
              let largeBlobReadInput = ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput.read
              authRequest.largeBlob = largeBlobReadInput
          }
      }
//        if #available(iOS 17.0, *) {
//          if let writeBlob = largeBlob["write"] as? Data {
//              let largeBlobWriteInput = ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput.write(writeBlob)
//              authRequest.largeBlob = largeBlobWriteInput
//          } else if let readBlob = largeBlob["read"] as? Bool, readBlob == true {
//            let largeBlobReadInput = ASAuthorizationPublicKeyCredentialLargeBlobAssertionInput.read
//            authRequest.largeBlob = largeBlobReadInput
//          }
//        }

        authController = ASAuthorizationController(authorizationRequests: [authRequest]);
      }

      // Set up a PasskeyDelegate instance with a callback function
      self.passKeyDelegate = PasskeyDelegate { error, result in
        // Check if authorization process returned an error and throw if thats the case
        if (error != nil) {
          let passkeyError = self.handleErrorCode(error: error!);
          reject(passkeyError.rawValue, passkeyError.rawValue, nil);
          return;
        }
        // Check if the result object contains a valid authentication result
        if let assertionResult = result?.assertionResult {
          // Return a NSDictionary instance with the received authorization data
            var authResponse: [String: Any] = [
                "rawAuthenticatorData": assertionResult.rawAuthenticatorData.base64EncodedString(),
                "rawClientDataJSON": assertionResult.rawClientDataJSON.base64EncodedString(),
                "signature": assertionResult.signature.base64EncodedString(),
            ]

            if #available(iOS 17.0, *), let largeBlob = assertionResult.largeBlob {
                switch largeBlob {
                case .read(let data):
                    if let data = data {
                        authResponse["read"] = data.base64EncodedString()
                    }
                case .write(let success):
                    authResponse["write"] = success
                }
            }

          let authResult: NSDictionary = [
            "credentialID": assertionResult.credentialID.base64EncodedString(),
            "userID": String(decoding: assertionResult.userID, as: UTF8.self),
            "response": authResponse
          ]
          resolve(authResult);
        } else {
          // If result didn't contain a valid authentication result throw an error
          reject(PassKeyError.requestFailed.rawValue, PassKeyError.requestFailed.rawValue, nil);
        }
      }

      if let passKeyDelegate = self.passKeyDelegate {
        // Perform the authorization request
        passKeyDelegate.performAuthForController(controller: authController);
      }
    } else {
      // If Passkeys are not supported throw an error
      reject(PassKeyError.notSupported.rawValue, PassKeyError.notSupported.rawValue, nil);
    }
  }

  // Handles ASAuthorization error codes
  func handleErrorCode(error: Error) -> PassKeyError {
    let errorCode = (error as NSError).code;
    switch errorCode {
      case 1001:
        return PassKeyError.cancelled;
      case 1004:
        return PassKeyError.requestFailed;
      case 4004:
        return PassKeyError.notConfigured;
      default:
        return PassKeyError.unknown;
    }
  }
}

enum PassKeyError: String, Error {
  case notSupported = "NotSupported"
  case requestFailed = "RequestFailed"
  case cancelled = "UserCancelled"
  case invalidChallenge = "InvalidChallenge"
  case notConfigured = "NotConfigured"
  case unknown = "UnknownError"
}

typealias LargeBlob = [String: Any]

struct AuthRegistrationResult {
  var passkey: PassKeyRegistrationResult
  var type: PasskeyOperation
}

struct AuthAssertionResult {
  var passkey: PassKeyAssertionResult
  var type: PasskeyOperation
}

struct PassKeyResult {
  var registrationResult: PassKeyRegistrationResult?
  var assertionResult: PassKeyAssertionResult?
}

struct PassKeyRegistrationResult {
  var credentialID: Data
  var rawAttestationObject: Data
  var rawClientDataJSON: Data
  var largeBlobSupported: Bool
}

struct PassKeyAssertionResult {
  var credentialID: Data
  var rawAuthenticatorData: Data
  var rawClientDataJSON: Data
  var signature: Data
  var userID: Data
  enum OperationResult {
        case read(data: Data?)
        case write(success: Bool)
    }
  var largeBlob: OperationResult?
}

enum PasskeyOperation {
  case Registration
  case Assertion
}

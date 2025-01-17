import type {
  PasskeyRegistrationResult,
  PasskeyRegistrationRequest,
  PasskeyAuthenticationRequest,
  PasskeyAuthenticationResult,
  LargeBlobExtension,
} from './Passkey';
import { handleNativeError } from './PasskeyError';
import { NativePasskey } from './NativePasskey';

export class PasskeyiOS {
  /**
   * iOS implementation of the registration process
   *
   * @param request The FIDO2 Attestation Request in JSON format
   * @param withSecurityKey A boolean indicating wether a security key should be used for registration
   * @returns The FIDO2 Attestation Result in JSON format
   */
  public static async register(
    request: PasskeyRegistrationRequest,
    withSecurityKey = false
  ): Promise<PasskeyRegistrationResult> {
    // Extract the required data from the attestation request
    const { rpId, challenge, name, userID, largeBlobSupport } =
      this.prepareRegistrationRequest(request);

    try {
      const response = await NativePasskey.register(
        rpId,
        challenge,
        name,
        userID,
        withSecurityKey,
        largeBlobSupport
      );
      return this.handleNativeRegistrationResult(response);
    } catch (error) {
      throw handleNativeError(error);
    }
  }

  /**
   * Extracts the data required for the attestation process on iOS from a given request
   */
  private static prepareRegistrationRequest(
    request: PasskeyRegistrationRequest
  ): PasskeyiOSRegistrationData {
    const extentions = request.extensions;
    if (extentions && extentions.largeBlob) {
      const largeBlob = extentions.largeBlob as LargeBlobExtension;
      if (largeBlob) {
        return {
          rpId: request.rp.id,
          challenge: request.challenge,
          name: request.user.displayName,
          userID: request.user.id,
          largeBlobSupport: largeBlob.support,
        };
      }
    }
    return {
      rpId: request.rp.id,
      challenge: request.challenge,
      name: request.user.displayName,
      userID: request.user.id,
    };
  }

  /**
   * Transform the iOS-specific attestation result into a FIDO2 result
   */
  private static handleNativeRegistrationResult(
    result: PasskeyiOSRegistrationResult
  ): PasskeyRegistrationResult {
    return {
      id: result.credentialID,
      rawId: result.credentialID,
      response: {
        clientDataJSON: result.response.rawClientDataJSON,
        attestationObject: result.response.rawAttestationObject,
        largeBlob: {
          supported: result.response.largeBlobSupported,
        },
      },
    };
  }

  /**
   * iOS implementation of the authentication process
   *
   * @param request The FIDO2 Assertion Request in JSON format
   * @param withSecurityKey A boolean indicating wether a security key should be used for authentication
   * @returns The FIDO2 Assertion Result in JSON format
   */
  public static async authenticate(
    request: PasskeyAuthenticationRequest,
    withSecurityKey = false
  ): Promise<PasskeyAuthenticationResult> {
    try {
      const response = await NativePasskey.authenticate(
        request.rpId,
        request.challenge,
        withSecurityKey,
        request.extensions?.largeBlob
      );
      return this.handleNativeAuthenticationResult(response);
    } catch (error) {
      throw handleNativeError(error);
    }
  }

  /**
   * Transform the iOS-specific assertion result into a FIDO2 result
   */
  private static handleNativeAuthenticationResult(
    result: PasskeyiOSAuthenticationResult
  ): PasskeyAuthenticationResult {
    return {
      id: result.credentialID,
      rawId: result.credentialID,
      response: {
        clientDataJSON: result.response.rawClientDataJSON,
        authenticatorData: result.response.rawAuthenticatorData,
        signature: result.response.signature,
        userHandle: result.userID,
        largeBlob: {
          read: result.response.read,
          written: result.response.write,
        },
      },
    };
  }
}

interface PasskeyiOSRegistrationData {
  rpId: string;
  challenge: string;
  name: string;
  userID: string;
  largeBlobSupport?: 'preferred' | 'required';
}

interface PasskeyiOSRegistrationResult {
  credentialID: string;
  response: {
    rawAttestationObject: string;
    rawClientDataJSON: string;
    largeBlobSupported: boolean;
  };
}

interface PasskeyiOSAuthenticationResult {
  credentialID: string;
  userID: string;
  response: {
    rawAuthenticatorData: string;
    rawClientDataJSON: string;
    signature: string;
    read?: string;
    write?: boolean;
  };
}

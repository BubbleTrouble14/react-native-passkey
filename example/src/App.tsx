import * as React from 'react';

import { Alert, Button, StyleSheet, View } from 'react-native';
import { Passkey } from 'react-native-passkey';

export default function App() {
  async function register() {
    try {
      // const result = await Passkey.register({
      //   challenge: 'nhkQXfE59Jb97VyyNJkvDiXucMEvltduvcrDmGrODHY',
      //   rp: {
      //     name: 'CredMan App Test',
      //     // id: 'test',
      //     // id: 'kayak.de',
      //     id: 'mintgarden.io',
      //     // id: 'https://mintgarden.io/.well-known/assetlinks.json',
      //   },
      //   user: {
      //     id: '2HzoHm_hY0CjuEESY9tY6-3SdjmNHOoNqaPDcZGzsr0',
      //     name: 'helloandroid@gmail.com',
      //     displayName: 'helloandroid@gmail.com',
      //   },
      //   pubKeyCredParams: [
      //     {
      //       type: 'public-key',
      //       alg: -7,
      //     },
      //     {
      //       type: 'public-key',
      //       alg: -257,
      //     },
      //   ],
      //   timeout: 1800000,
      //   attestation: 'none',
      //   excludeCredentials: [],
      //   authenticatorSelection: {
      //     authenticatorAttachment: 'platform',
      //     requireResidentKey: true,
      //     residentKey: 'required',
      //     userVerification: 'required',
      //   },
      // });
      const result = await Passkey.register({
        challenge: 'test',
        rp: {
          name: 'Passkey Test',
          id: 'mintgarden.io',
        },
        user: {
          id: '2HzoHm_hY0CjuEESY9tY6-3SdjmNHOoNqaPDcZGzsr0',
          name: 'Passkey Test',
          displayName: 'Passkey Test',
        },
        pubKeyCredParams: [
          {
            type: 'public-key',
            alg: -7,
          },
          {
            type: 'public-key',
            alg: -257,
          },
        ],
        timeout: 1800000,
        attestation: 'none',
        excludeCredentials: [],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          requireResidentKey: true,
          residentKey: 'required',
          userVerification: 'required',
        },
        extensions: {
          largeBlob: {
            support: 'preferred',
          },
        },
      });

      console.log('Registration result: ', result);
    } catch (e) {
      console.log(e);
    }
  }

  async function write() {
    try {
      const result = await Passkey.authenticate({
        // challenge: 'T1xCsnxM2DNL2KdK5CLa6fMhD7OBqho6syzInk_n-Uo',
        // allowCredentials: [],
        // timeout: 1800000,
        // userVerification: 'required',
        // rpId: 'mintgarden.io',
        challenge: 'test',
        allowCredentials: [],
        timeout: 1800000,
        userVerification: 'required',
        rpId: 'mintgarden.io',
        extensions: {
          largeBlob: {
            write:
              'c3dhbGxvdyBjb2luIHdvcmsgbWVudSBjb2luIHNsZW5kZXIgb25saW5lIGNyYXRlciByaXR1YWwgc2ltcGxlIGZlbmNlIGVtcGxveSBwcm9tb3RlIHNpbGx5IGRhd24gaW52ZXN0IG1ham9yIGJ1bmtlciB3aWZlIGJlY29tZSBzdWJtaXQgY291cnNlIHZpcnR1YWwgdHJpYmU=',
          },
        },
      });

      console.log('Authentication result: ', result);
    } catch (e) {
      console.log(e);
    }
  }

  async function read() {
    try {
      const result = await Passkey.authenticate({
        challenge: 'test',
        allowCredentials: [],
        timeout: 1800000,
        userVerification: 'required',
        rpId: 'mintgarden.io',
        extensions: {
          largeBlob: {
            read: true,
          },
        },
      });

      console.log('Authentication result: ', result);
    } catch (e) {
      console.log(e);
    }
  }

  async function isSupported() {
    const result = Passkey.isSupported();
    Alert.alert(result ? 'Supported' : 'Not supported');
  }

  return (
    <View style={styles.container}>
      <Button title="Register" onPress={register} />
      <Button title="Write" onPress={write} />
      <Button title="Read" onPress={read} />
      <Button title="isSupported?" onPress={isSupported} />
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    alignItems: 'center',
    justifyContent: 'space-evenly',
  },
  box: {
    width: 60,
    height: 60,
    marginVertical: 20,
  },
});

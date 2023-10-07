//  Created by Hao Pham, 27/04/2023
import 'dart:typed_data';
import 'package:convert/convert.dart';
import 'package:dmrtd/dmrtd.dart';
import 'package:dmrtd/extensions.dart';
import 'package:encrypt/encrypt.dart';
import 'package:elliptic/elliptic.dart';
import 'package:elliptic/ecdh.dart';
import '../crypto/kdf.dart';
import 'iso7816/icc.dart';
import 'mrtd_sm_pace.dart';
import 'ssc.dart';
import "package:pointycastle/export.dart" as pc;
import 'pace_smcipher.dart';

class PACEError implements Exception {
  final String message;
  PACEError(this.message);
  @override
  String toString() => message;
}

class PACE {

  static Future<void> initSession(
      {required PACEKeys keys,
      required Map securityInfos,
      required ICC icc}) async {
    final paceOID = securityInfos['PACEInfo']['paceOID'];
    final parameterSpec = securityInfos['PACEInfo']['parameterSpec'];
    final EllipticCurve brainpoolP256r1 = EllipticCurve(
      'brainpoolP256r1',
      256, // bitSize
      BigInt.parse(
          'a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377',
          radix: 16), // p
      BigInt.parse(
          '7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9',
          radix: 16), //a
      BigInt.parse(
          '26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6',
          radix: 16), //b
      BigInt.zero, //S
      AffinePoint.fromXY(
        BigInt.parse(
            '8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262',
            radix: 16),
        BigInt.parse(
            '547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997',
            radix: 16),
      ), // G
      BigInt.parse(
          'a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7',
          radix: 16), //N
      01, // h
    );
    // paceKeyType = PACEHandler.MRZ_PACE_KEY_REFERENCE
    final paceKeyType = 0x01;
    final paceKey = keys.encKey;
    final _ =
        await icc.sendMSESetATMutualAuth(oid: paceOID, keyType: paceKeyType);

    final decryptedNonce = await doStep1(icc: icc, paceKey: paceKey);

    final ephemeralParams = await doStep2(
        icc: icc, decryptedNonce: decryptedNonce, ec: brainpoolP256r1);

    final terminalKeyPairsAndICCPubKey =
        await doStep3KeyExchange(icc: icc, ephemeralParams: ephemeralParams);
    final ephemeralKeyPair = terminalKeyPairsAndICCPubKey["ephemeralKeyPair"];
    final passportPublicKey = terminalKeyPairsAndICCPubKey['passportPublicKey'];
    final encKey_macKey = await doStep4KeyAgreement(
        icc: icc,
        ephemeralKeyPair: ephemeralKeyPair,
        passportPublicKey: passportPublicKey,
        oid: paceOID);
    final encKey = encKey_macKey["encKey"];
    final macKey = encKey_macKey["macKey"];
    paceCompleted(icc: icc, encKey: encKey, macKey: macKey);
    // throw Exception("PACE Failed!");
    // throw "PACE Failed";
  }

  static Future<Uint8List> doStep1(
      {required ICC icc, required Uint8List paceKey}) async {
    final response = await icc.sendGeneralAuthenticate(
        data: Uint8List.fromList([0x7c, 0x00]), isLast: false);
    final data = response.data;

    final encryptedNonce = Encrypted(data!.sublist(4)); // Nhap, sua sau
    final key = Key(paceKey);
    final iv = IV(Uint8List.fromList(List.filled(16, 0)));
    final encrypter = Encrypter(AES(key, mode: AESMode.cbc, padding: null));
    final decryptedNonce = Uint8List.fromList(encrypter.decryptBytes(
      encryptedNonce,
      iv: iv,
    ));
    return decryptedNonce;
  }

  static Future<EllipticCurve> doStep2(
      {required ICC icc,
      required Uint8List decryptedNonce,
      required EllipticCurve ec}) async {
    // Create Private and Public key on brainpoolp256r1
    final mappingKey = ec.generatePrivateKey();
    var pcdMappingEncodedPublicKey = mappingKey.publicKey;
    final step2Data = [0x7c, 0x43, 0x81, 0x41] +
        hex.decode(pcdMappingEncodedPublicKey.toHex());
    final response = await icc.sendGeneralAuthenticate(
        data: Uint8List.fromList(step2Data), isLast: false);
    // Receive ICC Pubkey
    final data = response.data;
    final piccMappingEncodedPublicKey =
        PublicKey.fromHex(ec, hex.encode(data!.sublist(4)));

    // Create ephemeralParams
    var ephemeralParams = doECDHMappingAgreement(
        mappingKey: mappingKey,
        piccMappingEncodedPublicKey: piccMappingEncodedPublicKey,
        nonce: decryptedNonce);
    return ephemeralParams;
  }

  static Future<Map> doStep3KeyExchange(
      {required ICC icc, required EllipticCurve ephemeralParams}) async {
    var terminalKeyPairsAndICCPubKey = {};
    final terminalPrivateKey = ephemeralParams.generatePrivateKey();
    var terminalPublicKey = terminalPrivateKey.publicKey;
    // Send to ICC
    final step3Data =
        [0x7c, 0x43, 0x83, 0x41] + hex.decode(terminalPublicKey.toHex());
    final response = await icc.sendGeneralAuthenticate(
        data: Uint8List.fromList(step3Data), isLast: false);
    // Receive ICC Pubkey
    final data = response.data;
    final iccPublicKey =
        PublicKey.fromHex(ephemeralParams, hex.encode(data!.sublist(4)));

    terminalKeyPairsAndICCPubKey['ephemeralKeyPair'] = terminalPrivateKey;
    terminalKeyPairsAndICCPubKey['passportPublicKey'] = iccPublicKey;
    return terminalKeyPairsAndICCPubKey;
  }

  static Future<Map> doStep4KeyAgreement(
      {required ICC icc,
      required PrivateKey ephemeralKeyPair,
      required PublicKey passportPublicKey,
      required Uint8List oid}) async {
    final keySeed = Uint8List.fromList(
        hex.decode(computeSecretHex(ephemeralKeyPair, passportPublicKey)));
    final encKey = DeriveKey.aes128(keySeed);
    final macKey = DeriveKey.cmac128(keySeed);
    var encKey_macKey = {};
    encKey_macKey['encKey'] = encKey;
    encKey_macKey['macKey'] = macKey;

    // Step 4 - generate authentication token
    final pcdAuthToken =
        generateAuthenticationToken(passportPublicKey, macKey, oid);
    final step4Data = [0x7c, 0x0a, 0x85, 0x08] + pcdAuthToken;
    final response = await icc.sendGeneralAuthenticate(
        data: Uint8List.fromList(step4Data), isLast: true);
    final data = response.data!.sublist(4);
    final expectedPICCToken =
        generateAuthenticationToken(ephemeralKeyPair.publicKey, macKey, oid);
    if (expectedPICCToken.hex() == data.hex()) {
      print("Auth token from passport matches expected token!");
    } else {
      print("Wrong Token!!!!");
      throw Exception("Wrong TOKEN");
    }
    return encKey_macKey;
  }

  static Uint8List generateAuthenticationToken(
      PublicKey pubkey, Uint8List macKey, Uint8List oid) {
    var authData = Uint8List.fromList([0x7f, 0x49, 0x4f] +
        [0x06, 0x0a] +
        oid.sublist(1) +
        [0x86, 0x41] +
        hex.decode(pubkey.toHex()));
    // hex.decode(pubkey_test));
    final cmac = pc.CMac(pc.AESEngine(), 64);
    cmac.init(pc.KeyParameter(macKey));
    final authToken = cmac.process(authData);
    return authToken;
  }

  static EllipticCurve doECDHMappingAgreement(
      {required PrivateKey mappingKey,
      required PublicKey piccMappingEncodedPublicKey,
      required Uint8List nonce}) {
    final ec = mappingKey.curve;
    final H = ec.scalarMul(piccMappingEncodedPublicKey, mappingKey.bytes);
    final G_hat = ec.add(ec.scalarBaseMul(nonce), H);
    final EllipticCurve ephemeralParams = EllipticCurve(
      'brainpoolP256r1',
      256, // bitSize
      BigInt.parse(
          'a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377',
          radix: 16), // p
      BigInt.parse(
          '7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9',
          radix: 16), //a
      BigInt.parse(
          '26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6',
          radix: 16), //b
      BigInt.zero, //S
      G_hat, // G
      BigInt.parse(
          'a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7',
          radix: 16), //N
      01, // h
    );
    return ephemeralParams;
  }

  static void paceCompleted(
      {required ICC icc,
      required Uint8List encKey,
      required Uint8List macKey}) {
    final ssc = SSC(Uint8List.fromList([0x00]), 64);
    icc.sm = MrtdSMPACE(PACE_SMCipher(encKey, macKey), ssc, encKey, macKey);
    return;
  }
}

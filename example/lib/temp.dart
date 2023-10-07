import 'package:flutter/foundation.dart';
import 'package:dmrtd/dmrtd.dart';
import 'package:crypto/crypto.dart';
import 'package:pkcs7/pkcs7.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:pointycastle/src/utils.dart';
import 'package:ecdsa/ecdsa.dart' as ecdsa;
import 'package:elliptic/elliptic.dart' as ecc;
import 'package:mrtdeg/curves.dart';

bool v1_verify(EfDG15 dg15, EfSOD sod) {
  var verify_result = true;
  final dg15_digest = sha256.convert(dg15.toBytes());

  final datagroup_digests = {
    15: dg15_digest,
  };

  final sod_pkcs7_raw = sod.toBytes().sublist(4);
  final sod_pkcs7 = Pkcs7(ASN1Sequence.fromBytes(sod_pkcs7_raw));
  // skip 4 bytes implicit + 4 bytes octetstring
  final encapsulatedContent = sod_pkcs7.encapsulatedContent!.sublist(8);
  final dg_digest = sha256.convert(encapsulatedContent);

  final digest_list =
      ASN1Sequence.fromBytes(encapsulatedContent).elements![2] as ASN1Sequence;
  for (var digest_item in digest_list.elements!) {
    final item = (digest_item as ASN1Sequence).elements!;
    final dg_number = (item[0] as ASN1Integer).integer!.toInt();
    if (dg_number != 15) {
      continue;
    }
    final dg_digest = item[1].valueBytes!;
    final calculated_digest = datagroup_digests[dg_number]!;
    final matched = listEquals(calculated_digest.bytes, dg_digest);
    verify_result &= matched;
  }

  final signer = sod_pkcs7.signerInfo.first;
  final signer_asn1 = signer.asn1;
  final message = signer_asn1.elements![3];
  final sign_message_body = message.valueBytes!;
  final sign_message = Uint8List.fromList(
      [0x31, message.valueByteLength!, ...sign_message_body]);
  final message_decoded = ASN1Set.fromBytes(sign_message);
  var is_digest_correct = false;
  for (var item in message_decoded.elements!) {
    var wrapper = item as ASN1Sequence;
    var nested_item = wrapper.elements![1] as ASN1Set;
    var value = nested_item.valueBytes!.sublist(2); // skip 2 bytes tag,length
    is_digest_correct |= listEquals(value, dg_digest.bytes);
  }
  verify_result &= is_digest_correct;

  final sign_digest = sha256.convert(sign_message);
  final sign_digest_number = decodeBigInt(sign_digest.bytes);

  final signature_raw = ASN1Sequence.fromBytes(signer.signature);
  final r_raw = signature_raw.elements![0] as ASN1Integer;
  final s_raw = signature_raw.elements![1] as ASN1Integer;

  final r = r_raw.integer;
  final s = s_raw.integer;

  final certificate = sod_pkcs7.certificates.first;
  final pubkey_raw = certificate.publicKeyBytes.sublist(1); // skip 04

  final pub_x = decodeBigInt(pubkey_raw.sublist(0, pubkey_raw.length ~/ 2));
  final pub_y = decodeBigInt(pubkey_raw.sublist(pubkey_raw.length ~/ 2));

  final cert_signature_raw =
      ASN1Sequence.fromBytes(certificate.signatureValue.sublist(1));
  final cert_r_raw = cert_signature_raw.elements![0] as ASN1Integer;
  final cert_s_raw = cert_signature_raw.elements![1] as ASN1Integer;
  final cert_r = cert_r_raw.integer;
  final cert_s = cert_s_raw.integer;

  final tbs_cert_data = certificate.asn1.elements![0].encodedBytes;
  final cert_digest = sha384.convert(tbs_cert_data!);
  final cert_digest_number = decodeBigInt(cert_digest.bytes);

  // verify signed data with brainpoolP384r1
  // verify_ecdsa(sign_digest_number, (r, s), (pub_x, pub_y));

  final cert_pubkey = ecc.PublicKey(brainpoolP384r1, pub_x, pub_y);
  final verified_signeddata = ecdsa.verify(
      cert_pubkey, sign_digest.bytes, ecdsa.Signature.fromRS(r!, s!));

  // This is CA
  final ca_pub_x = BigInt.parse(
      "5705586746797687392276527904990313555022905475611271258729414636068323857880334000957361424951661974682935706611888");
  final ca_pub_y = BigInt.parse(
      "7821704373206592378644977211567592118672246135776362491204878202396889655625917188376232816427307041739256606332695");

  final ca_pubkey = ecc.PublicKey(nist384r1, ca_pub_x, ca_pub_y);
  final verified_cert = ecdsa.verify(
      ca_pubkey, cert_digest.bytes, ecdsa.Signature.fromRS(cert_r!, cert_s!));

  verify_result &= verified_signeddata;
  verify_result &= verified_cert;
  return verify_result;
}

bool v2_verify(Uint8List m2, Uint8List signature, EfDG15 dg15) {
  final rawSubPubKey = dg15.aaPublicKey.rawSubjectPublicKey();
  final tvSubPubKey = TLV.fromBytes(rawSubPubKey);
  var rawSeq = tvSubPubKey.value;
  if (rawSeq[0] == 0x00) {
    rawSeq = rawSeq.sublist(1);
  }

  final tvKeySeq = TLV.fromBytes(rawSeq);
  final tvModulus = TLV.decode(tvKeySeq.value);
  final tvExp = TLV.decode(tvKeySeq.value.sublist(tvModulus.encodedLen));

  final n = decodeBigInt(tvModulus.value);

  final signature_raw = decodeBigIntWithSign(1, signature);
  final message_decrypted = signature_raw.modPow(BigInt.from(65537), n);
  final message_raw = encodeBigInt(message_decrypted);

  final t = message_raw[message_raw.length - 1] == 0xbc ? 1 : 2;
  final hashlen = 160;

  final k = n.bitLength;
  final m1_len = ((k - hashlen - 8 * t - 4) - 4);

  // bits 01 default bit
  // bit 1 partial recovery
  // bit 1 end of padding
  // k - hash_len - m1_len - 8t - 4 bits padding
  final pad = (2 + 1 + 1 + k - hashlen - m1_len - 8 * t - 4);

  final m1_len_bytes = m1_len ~/ 8;
  final pad_bytes = pad ~/ 8;
  final hash_len_bytes = hashlen ~/ 8;

  final message_end = pad_bytes + m1_len_bytes;
  final hash_end = message_end + hash_len_bytes;

  final m1 = message_raw.sublist(pad_bytes, message_end);
  final hash = message_raw.sublist(message_end, hash_end.toInt());
  return listEquals(hash, sha1.convert([...m1, ...m2]).bytes);
}

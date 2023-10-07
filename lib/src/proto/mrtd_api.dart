// Created by Crt Vavros, copyright © 2022 ZeroPass. All rights reserved.
import 'dart:typed_data';

import 'package:dmrtd/dmrtd.dart';
import 'pace.dart';
import 'iso7816/iso7816.dart';
import 'iso7816/icc.dart';
import 'iso7816/response_apdu.dart';
import '../lds/df1/df1.dart';
import '../utils.dart';

import 'package:dmrtd/extensions.dart';

class MrtdApiError implements Exception {
  final String message;
  final StatusWord? code;
  const MrtdApiError(this.message, {this.code});
  @override
  String toString() => "MRTDApiError: $message";
}

/// Defines ICAO 9303 MRTD standard API to
/// communicate and send commands to MRTD.
/// TODO: Add ComProvider onConnected notifier and reset _maxRead to _defaultReadLength on new connection
class MrtdApi {
  static const int challengeLen = 8; // 8 bytes
  ICC icc;

  MrtdApi(ComProvider com) : icc = ICC(com);

  // See: Section 4.1 https://www.icao.int/publications/Documents/9303_p10_cons_en.pdf
  static const _defaultSelectP2 =
      ISO97816_SelectFileP2.returnFCP | ISO97816_SelectFileP2.returnFMD;
  static const int _defaultReadLength =
      256; // 256 = expect maximum number of bytes. TODO: in production set it to 224 - JMRTD
  int _maxRead = _defaultReadLength;
  static const int _readAheadLength =
      8; // Number of bytes to read at the start of file to determine file length.
  Future<void> Function()? _reinitSession;

  /// Sends active authentication command to MRTD with [challenge].
  /// [challenge] must be 8 bytes long.
  /// MRTD returns signature of size [sigLength] or of arbitrarily size if [sigLength] is 256.
  /// Can throw [ICCError] if [challenge] is not 8 bytes or [sigLength] is wrong signature length.
  /// Can throw [ComProviderError] in case connection with MRTD is lost.
  Future<Uint8List> activeAuthenticate(final Uint8List challenge,
      {int sigLength = 256}) async {
    // assert(challenge.length == challengeLen);
    return await icc.internalAuthenticate(data: challenge, ne: sigLength);
  }

  Future<void> initSessionViaPACE(
      final PACEKeys keys, final Map securityInfos) async {
    await PACE.initSession(keys: keys, securityInfos: securityInfos, icc: icc);
    _reinitSession = () async {
      icc.sm = null;
      await PACE.initSession(
          keys: keys, securityInfos: securityInfos, icc: icc);
    };
  }

  /// Selects eMRTD application (DF1) applet.
  /// Can throw [ICCError] if command is sent to invalid MRTD document.
  /// Can throw [ComProviderError] in case connection with MRTD is lost.
  Future<void> selectEMrtdApplication() async {
    await icc.selectFileByDFName(dfName: DF1.AID, p2: _defaultSelectP2);
    // await icc.selectParentDF(dfName: DF1.AID, p2: _defaultSelectP2)
    // Uint8List? response =
    //     await icc.selectParentDF(p2: 0x01, cla: ISO7816_CLA.NO_SM, ne: 0x00);
    // if (response != null) {
    //   _log.debug(response.hex());
    // } else {
    //   _log.debug('NULLLLLLLLLLLLLLLLLL');
    // }
  }

  /// Selects Master File (MF).
  /// Can throw [ICCError] if command is sent to invalid MRTD document.
  /// Can throw [ComProviderError] in case connection with MRTD is lost.
  Future<void> selectMasterFile() async {
    // In ICAO 9303 p10 doc, the command to select Master File is defined as sending select APDU
    // command with empty data field. On some passport this command doesn't work and MF is not selected,
    // although success status (9000) is returned. In doc ISO/IEC 7816-4 section 6 an alternative option
    // is specified by sending the same command as described in ICAO 9303 p10 doc but in this case
    // data field should be equal to '0x3F00'.
    // see: https://cardwerk.com/smart-card-standard-iso7816-4-section-6-basic-interindustry-commands
    //     'If P1-P2=’0000′ and if the data field is empty or equal to ‘3F00’, then select the MF.'
    //
    // To maximize our chance for MF to be selected we send select first command with P1-P2=’0000′ as
    // specified in doc ISO/IEC 7816-4 section 6.

    // await icc
    //     .selectFile(cla: ISO7816_CLA.NO_SM, p1: 0, p2: 0)
    //     .onError<ICCError>((error, stackTrace) async {
    //   _log.warning(
    //       "Couldn't select MF by P1: 0, P2: 0 sw=${error.sw}, re-trying to select MF with FileID=3F00");
    //   return await icc
    //       .selectFile(
    //           cla: ISO7816_CLA.NO_SM,
    //           p1: 0,
    //           p2: 0,
    //           data: Uint8List.fromList([0x3F, 0x00]))
    //       .onError<ICCError>((error, stackTrace) async {
    //     _log.warning(
    //         "Couldn't select MF by P1=0, P2=0, FileID=3F00 sw=${error.sw}, re-trying to select MF with P2=0x0C and FileID=3F00");
    //     return await icc
    //         .selectFileById(
    //             p2: _defaultSelectP2, fileId: Uint8List.fromList([0x3F, 0x00]))
    //         .onError<ICCError>((error, stackTrace) async {
    //       _log.warning(
    //           "Couldn't select MF by P1=0, P2=0x0C, FileID=3F00 sw=${error.sw}, re-trying to select MF with P2=0x0C");
    //       return await icc.selectFile(
    //           cla: ISO7816_CLA.NO_SM, p1: 0, p2: _defaultSelectP2);
    //     });
    //   });
    // });
    for (int i = 0; i < 256; i++) {
      try {
        await icc.selectFile(
            cla: ISO7816_CLA.NO_SM,
            p1: 0x00,
            p2: i,
            data: Uint8List.fromList([0x3F, 0x00]));
        return;
      } on ICCError catch (e) {
        print("$i selectFile done!");
      }
    }
    // await icc.selectFile(
    //     cla: ISO7816_CLA.NO_SM,
    //     p1: 0x00,
    //     p2: 0x00,
    //     data: Uint8List.fromList([0x3F, 0x00]));
  }

  /// Returns raw EF file bytes of selected DF identified by [fid] from MRTD.
  /// Can throw [ICCError] in case when file doesn't exist, read errors or
  /// SM session is not established but required to read file.
  /// Can throw [ComProviderError] in case connection with MRTD is lost.
  Future<Uint8List> readFile(final int fid) async {
    if (fid > 0xFFFF) {
      throw MrtdApiError("Invalid fid=0x${Utils.intToBin(fid).hex()}");
    }

    // Select EF file first
    final efId = Uint8List(2);
    ByteData.view(efId.buffer).setUint16(0, fid);
    await icc.selectEF(efId: efId, p2: _defaultSelectP2);

    // Read chunk of file to obtain file length
    final chunk1 = await icc.readBinary(offset: 0, ne: _readAheadLength);
    final dtl = TLV.decodeTagAndLength(chunk1.data!);

    // Read the rest of the file
    final length = dtl.length.value - (chunk1.data!.length - dtl.encodedLen);
    final chunk2 =
        await _readBinary(offset: chunk1.data!.length, length: length);

    final rawFile = Uint8List.fromList(chunk1.data! + chunk2);
    assert(rawFile.length == dtl.encodedLen + dtl.length.value);
    return rawFile;
  }

  /// Returns raw EF file bytes of selected DF identified by short file identifier [sfid] from MRTD.
  /// Can throw [ICCError] in case when file doesn't exist, read errors or
  /// SM session is not established but required to read file.
  /// Can throw [ComProviderError] in case connection with MRTD is lost.
  Future<Uint8List> readFileBySFI(int sfi) async {
    sfi |= 0x80;
    if (sfi > 0x9F) {
      throw ArgumentError.value(sfi, null, "Invalid SFI value");
    }

    // Read chunk of file to obtain file length
    final chunk1 =
        await icc.readBinaryBySFI(sfi: sfi, offset: 0, ne: _readAheadLength);
    final dtl = TLV.decodeTagAndLength(chunk1.data!);
    // Read the rest of the file
    final length = dtl.length.value - (chunk1.data!.length - dtl.encodedLen);
    final chunk2 =
        await _readBinary(offset: chunk1.data!.length, length: length);

    final rawFile = Uint8List.fromList(chunk1.data! + chunk2);
    assert(rawFile.length == dtl.encodedLen + dtl.length.value);
    return rawFile;
  }

  /// Reads [length] long fragment of file starting at [offset].
  Future<Uint8List> _readBinary(
      {required int offset, required int length}) async {
    var data = Uint8List(0);
    while (length > 0) {
      int nRead = length;
      if (length > _maxRead) {
        nRead = _maxRead;
      }
      try {
        ResponseAPDU rapdu;
        if (offset > 0x7FFF) {
          // extended read binary
          rapdu = await icc.readBinaryExt(offset: offset, ne: nRead);
        } else {
          if (offset + nRead > 0x7FFF) {
            // Do not overlap offset 32 767 with even READ BINARY command
            nRead = 0x7FFF - offset;
          }
          rapdu = await icc.readBinary(offset: offset, ne: nRead);
        }

        if (rapdu.status.sw1 == StatusWord.sw1SuccessWithRemainingBytes) {
          // This should probably happen only in case of calling
          // command GET STATUS, which we don't call here.
          // We log it for tracing purpose.
        } else if (rapdu.status == StatusWord.unexpectedEOF) {
          _reduceMaxRead();
        } else if (rapdu.status == StatusWord.possibleCorruptedData) {
        } else if (rapdu.status.isError()) {
          // Just making sure if an error has occured we still have valid session
          await _reinitSession?.call();
        }

        if (rapdu.data != null) {
          data = Uint8List.fromList(data + rapdu.data!);
          offset += rapdu.data!.length;
          length -= rapdu.data!.length;
        } else {
        }
      } on ICCError catch (e) {
        // thrown on _readBinary error when no data is received.
        if (e.sw == StatusWord.wrongLength && _maxRead != 1) {
          // if _maxRead == 1 then we tried all possible lengths and failed, so this check should throw us out of the loop
          _reduceMaxRead();
        } else if (e.sw.sw1 == StatusWord.sw1WrongLengthWithExactLength) {
          _maxRead = e.sw.sw2;
        } else {
          _maxRead = _defaultReadLength;
          throw MrtdApiError(
              "An error has occurred while trying to read file chunk.",
              code: e.sw);
        }
        if (e.sw.isError()) {
          // Just a sanity check as ICCError is thrown only on error
          await _reinitSession?.call();
        }
      }
    }

    // Verify total received data size is not greater than
    // requested and remove excess data.
    // Some passports e.g.: Slovenian on SW:0x6282 (unexpectedEOF)
    // add possible wrong pad data: 0x000080 instead of 0x800000.
    if (length < 0) {
      final newSize = data.length - length.abs();
      data = data.sublist(0, newSize);
    }

    return data;
  }

  void _reduceMaxRead() {
    if (_maxRead > 224) {
      _maxRead = 224; // JMRTD lib's default read size
    } else if (_maxRead > 160) {
      // Some passports can't handle more then 160 bytes per read
      _maxRead = 160;
    } else if (_maxRead > 128) {
      _maxRead = 128;
    } else if (_maxRead > 96) {
      _maxRead = 96;
    } else if (_maxRead > 64) {
      _maxRead = 64;
    } else if (_maxRead > 32) {
      _maxRead = 32;
    } else if (_maxRead > 16) {
      _maxRead = 16;
    } else if (_maxRead > 8) {
      _maxRead = 8;
    } else {
      _maxRead = 1; // last resort try to read 1 byte at the time
    }
  }
}
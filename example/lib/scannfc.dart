import 'dart:convert';
import 'package:mrtdeg/http/vote_http.dart';
import 'package:dmrtd/internal.dart';
import 'package:flutter/material.dart';
import 'dart:async';
import 'package:dmrtd/dmrtd.dart';
import 'package:crypto/crypto.dart';
import 'package:convert/convert.dart';
import 'dart:typed_data';
import 'package:flutter/services.dart';
import 'package:flutter_platform_widgets/flutter_platform_widgets.dart';
import 'package:intl/intl.dart';
import 'package:mrtdeg/mrtd.dart';
import 'package:mrtdeg/user_page.dart';

class ScanIdCard extends StatefulWidget {
  final Mrz mrz;

  ScanIdCard({required this.mrz});

  @override
  // ignore: library_private_types_in_public_api
  _MrtdHomePageState createState() => _MrtdHomePageState();
}

class _MrtdHomePageState extends State<ScanIdCard> {
  var _alertMessage = "";
  var _isNfcAvailable = false;
  var _isReading = false;
  // final _mrzData = GlobalKey<FormState>();

  // mrz data
  final _docNumber = TextEditingController();
  final _dob = TextEditingController(); // date of birth
  final _doe = TextEditingController(); // date of doc expiry
  VoteHttp voteHttp = VoteHttp();
  MrtdData? _mrtdData;
  String? _k;
  final NfcProvider _nfc = NfcProvider();
  // ignore: unused_field
  late Timer _timerStateUpdater;
  final _scrollController = ScrollController();

  @override
  void initState() {
    super.initState();
    SystemChrome.setPreferredOrientations([
      DeviceOrientation.portraitUp,
      DeviceOrientation.portraitDown,
    ]);

    _initPlatformState();

    // Update platform state every 3 sec
    _timerStateUpdater = Timer.periodic(Duration(seconds: 3), (Timer t) {
      _initPlatformState();
    });
  }

  // Platform messages are asynchronous, so we initialize in an async method.
  Future<void> _initPlatformState() async {
    bool isNfcAvailable;
    try {
      NfcStatus status = await NfcProvider.nfcStatus;
      isNfcAvailable = status == NfcStatus.enabled;
    } on PlatformException {
      isNfcAvailable = false;
    }

    // If the widget was removed from the tree while the asynchronous platform
    // message was in flight, we want to discard the reply rather than calling
    // setState to update our non-existent appearance.
    if (!mounted) return;

    if (_isNfcAvailable == isNfcAvailable) {
      return;
    }

    setState(() {
      _isNfcAvailable = isNfcAvailable;
    });
  }

  DateTime? _getDOBDate() {
    if (_dob.text.isEmpty) {
      return null;
    }
    return DateFormat.yMd().parse(_dob.text);
  }

  DateTime? _getDOEDate() {
    if (_doe.text.isEmpty) {
      return null;
    }
    return DateFormat.yMd().parse(_doe.text);
  }

  Future<String?> _pickDate(BuildContext context, DateTime firstDate,
      DateTime initDate, DateTime lastDate) async {
    final locale = Localizations.localeOf(context);
    final DateTime? picked = await showDatePicker(
        context: context,
        firstDate: firstDate,
        initialDate: initDate,
        lastDate: lastDate,
        locale: locale);

    if (picked != null) {
      return DateFormat.yMd().format(picked);
    }
    return null;
  }

  BigInt bytes2bigint(Uint8List bytes) {
    BigInt result = BigInt.zero;

    for (final byte in bytes) {
      // reading in big-endian, so we essentially concat the new byte to the end
      result = (result << 8) | BigInt.from(byte & 0xff);
    }
    return result;
  }

  void _readMRTD() async {
    var succeed = false;
    try {
      setState(() {
        _mrtdData = null;
        _alertMessage = "Waiting for ID Card tag ...";
        _isReading = true;
      });

      await _nfc.connect(iosAlertMessage: "Hold your phone near ID Card");
      final passport = Passport(_nfc);

      setState(() {
        _alertMessage = "Reading ID Card ...";
      });
      var skipPACE = true;
      _nfc.setIosAlertMessage("Trying to read EF.CardAccess ...");
      final mrtdData = MrtdData();
      try {
        mrtdData.cardAccess = await passport.readEfCardAccess();
        skipPACE = false;
      } on PassportError {
        skipPACE = false;
      }
      _nfc.setIosAlertMessage("Initiating session ...");
      if (skipPACE == false) {
        try {
          var data = mrtdData.cardAccess;
          var securityInfos = getSecurityInfos(data);
          final paceKeySeed =
              PACEKeys(widget.mrz.id, widget.mrz.birthday, widget.mrz.expiry);
          await passport.startSessionPACE(paceKeySeed, securityInfos);
        } on Exception catch (e) {
          skipPACE = true;
        }
      }
      _nfc.setIosAlertMessage(formatProgressMsg("Reading EF.COM ...", 0));
      mrtdData.com = await passport.readEfCOM();

      _nfc.setIosAlertMessage(formatProgressMsg("Reading EF.SOD ...", 80));
      mrtdData.sod = await passport.readEfSOD();

      _nfc.setIosAlertMessage(formatProgressMsg("Reading Data Groups ...", 20));

      if (mrtdData.com!.dgTags.contains(EfDG1.TAG)) {
        mrtdData.dg1 = await passport.readEfDG1();
      }

      if (mrtdData.com!.dgTags.contains(EfDG2.TAG)) {
        mrtdData.dg2 = await passport.readEfDG2();
      }

      if (mrtdData.com!.dgTags.contains(EfDG5.TAG)) {
        mrtdData.dg5 = await passport.readEfDG5();
      }

      if (mrtdData.com!.dgTags.contains(EfDG6.TAG)) {
        mrtdData.dg6 = await passport.readEfDG6();
      }

      if (mrtdData.com!.dgTags.contains(EfDG7.TAG)) {
        mrtdData.dg7 = await passport.readEfDG7();
      }

      if (mrtdData.com!.dgTags.contains(EfDG8.TAG)) {
        mrtdData.dg8 = await passport.readEfDG8();
      }

      if (mrtdData.com!.dgTags.contains(EfDG9.TAG)) {
        mrtdData.dg9 = await passport.readEfDG9();
      }

      if (mrtdData.com!.dgTags.contains(EfDG10.TAG)) {
        mrtdData.dg10 = await passport.readEfDG10();
      }

      if (mrtdData.com!.dgTags.contains(EfDG11.TAG)) {
        mrtdData.dg11 = await passport.readEfDG11();
      }

      if (mrtdData.com!.dgTags.contains(EfDG12.TAG)) {
        mrtdData.dg12 = await passport.readEfDG12();
      }

      if (mrtdData.com!.dgTags.contains(EfDG13.TAG)) {
        mrtdData.dg13 = await passport.readEfDG13();
      }

      if (mrtdData.com!.dgTags.contains(EfDG14.TAG)) {
        mrtdData.dg14 = await passport.readEfDG14();
      }

      if (mrtdData.com!.dgTags.contains(EfDG15.TAG)) {
        mrtdData.dg15 = await passport.readEfDG15();
      }
      // Doing Passive Authentication
      final pa_verify = verify_sod(mrtdData);
      if (pa_verify) {
        final k = randomBytes(8); // Secret key in H(uid||k)
        int k_decimal = ByteData.view(k.buffer).getUint16(0, Endian.little);
        print("k = $k");
        print("k_dec = $k_decimal");
        // h should be mimc hash
        // final h =
        //     sha256.convert(Uint8List.fromList(utf8.encode(widget.mrz.id)) + k);
        final h_mimc =
            await voteHttp.getMimcHash(widget.mrz.id, k_decimal.toString());
        print("h_mimc = $h_mimc");

        _nfc.setIosAlertMessage(formatProgressMsg("Doing AA ...", 60));
        final h_bytes = hex.decode(BigInt.parse(h_mimc).toRadixString(16));
        mrtdData.authData = Uint8List.fromList(h_bytes.sublist(0, 8));
        mrtdData.aaSig = await passport.activeAuthenticate(mrtdData.authData!);
        final aa_verify = verify_active_auth(
            mrtdData.authData!, mrtdData.aaSig!, mrtdData.dg15!);
        if (aa_verify) {
          final response = await voteHttp.register(
              hex.encode(h_bytes),
              hex.encode(mrtdData.aaSig!),
              hex.encode(mrtdData.dg15!.toBytes()),
              hex.encode(mrtdData.sod!.toBytes()));
          // Send (h, aaSig, dg15, SOD) to Blockchain
          if (response == null) {
            
          }
          if (response["msg"] == 'succeed') {
            print("OK!");
            setState(() {
              _mrtdData = mrtdData;
              _k = k_decimal.toString();
            });

            setState(() {
              _alertMessage = "";
            });
          }
        } else {
          setState(() {
            _alertMessage = "Cloning Chip";
          });
          throw Exception("Cloning Chip");
        }
      } else {
        setState(() {
          _alertMessage = "Tempered Chip";
        });
        throw Exception("Tempered Chip");
      }
      succeed = true;
      _scrollController.animateTo(300.0,
          duration: Duration(milliseconds: 500), curve: Curves.ease);
    } on Exception catch (e) {
      final se = e.toString().toLowerCase();
      String alertMsg =
          "An error has occurred while reading ID Card! Please hold your phone near the ID card and re-read.";
      if (e is PassportError) {
        if (se.contains("security status not satisfied")) {
          alertMsg =
              "Failed to initiate session with passport.\nCheck input data!";
        }
      } else {}

      if (se.contains('timeout')) {
        alertMsg = "Timeout while waiting for Passport tag";
      } else if (se.contains("tag was lost")) {
        alertMsg = "Tag was lost. Please try again!";
      } else if (se.contains("invalidated by user")) {
        alertMsg = "";
      }

      setState(() {
        _alertMessage = alertMsg;
      });
    } finally {
      if (_alertMessage.isNotEmpty) {
        await _nfc.disconnect(iosErrorMessage: _alertMessage);
      } else {
        await _nfc.disconnect(
            iosAlertMessage: formatProgressMsg("Finished", 100));
      }
      setState(() {
        _isReading = false;
      });
      if (succeed) {
        Navigator.push(
          context,
          MaterialPageRoute(
            builder: (context) =>
                UserPage(mrtdData: _mrtdData!, k: _k!),
          ),
        );
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return PlatformProvider(
        builder: (BuildContext context) => _buildPage(context));
  }

  PlatformScaffold _buildPage(BuildContext context) => PlatformScaffold(
      appBar: PlatformAppBar(title: Text('BShield ID card verifier')),
      iosContentPadding: false,
      iosContentBottomPadding: false,
      body: Material(
          child: SafeArea(
              child: Padding(
                  padding: EdgeInsets.all(8.0),
                  child: SingleChildScrollView(
                      controller: _scrollController,
                      child: Column(
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: <Widget>[
                            SizedBox(height: 20),
                            Row(children: <Widget>[
                              Text('NFC available:',
                                  style: TextStyle(
                                      fontSize: 18.0,
                                      fontWeight: FontWeight.bold)),
                              SizedBox(width: 4),
                              Text(_isNfcAvailable ? "Yes" : "No",
                                  style: TextStyle(fontSize: 18.0))
                            ]),
                            SizedBox(height: 20),
                            // _buildForm(context),
                            SizedBox(height: 20),
                            TextButton(
                              // btn Read MRTD
                              onPressed: _readMRTD,
                              child: PlatformText(
                                  _isReading ? 'Reading ...' : 'Read Card'),
                            ),
                          ]))))));
}

import 'dart:typed_data';
import 'dart:convert';
import 'package:convert/convert.dart';
void main() {
  String myNum = "12345";
  BigInt R = BigInt.parse(myNum, radix: 10);
  final h = R.toRadixString(16);
//   List<int> list = utf8.encode(R.toRadixString(16));
  Uint8List bytes = Uint8List.fromList(hex.decode(h));
  print(bytes);
}
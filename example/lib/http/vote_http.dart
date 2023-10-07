import 'dart:convert';
import 'package:http/http.dart' as http;

String plonkServer = "192.168.43.2:3000";
String blockchainServer = "192.168.43.2:3007";

class VoteHttp {
  /// Fetches candidates
  ///
  /// @returns Candidate list with hex values
  Future<List<dynamic>> getCandidates() async {
    http.Response response =
        await http.get(Uri.http(blockchainServer, "/candidates"));

    if (response.statusCode == 200) {
      final candidates = json.decode(response.body)["candidates"];
      return candidates;
    } else {
      throw Exception("Error in candidates");
    }
  }

  Future<Map<dynamic, dynamic>> register(
      String h_hex, String aaSig_hex, String dg15_hex, String sod_hex) async {
    http.Response response = await http.post(
        Uri.http(blockchainServer, "/register"),
        headers: {"Content-type": "application/json"},
        body: jsonEncode(<String, String>{
          "h": h_hex,
          "aaSig": aaSig_hex,
          "dg15": dg15_hex,
          "sod": sod_hex
        }));
    return json.decode(response.body);
  }

  /// Cast the vote for selected candidate
  ///
  /// @param candidateNum - int Index of the selected candidate
  /// @param from - String Voter's accound address
  /// @return Response body
  Future<Map<String, dynamic>> castVote(int candidateNum, String from) async {
    http.Response response = await http.post(Uri.http("10.0.2.2:8082", "/vote"),
        headers: {"Content-type": "application/json"},
        body: jsonEncode(<String, String>{
          "candidate": candidateNum.toString(),
          "from": from
        }));

    if (response.statusCode == 200) {
      return json.decode(response.body);
    } else if (response.statusCode == 404) {
      return json.decode(response.body);
    } else {
      throw Exception("Unsuccessful voting.");
    }
  }

  /// Checks voter's vote
  ///
  /// @param from - String Voter's account address
  /// @returns Response body
  Future<Map<String, dynamic>> checkMyVote(String from) async {
    http.Response response = await http.post(
        Uri.http("10.0.2.2:8082", "/get/check-my-vote"),
        headers: {"Content-type": "application/json"},
        body: jsonEncode(<String, String>{"from": from}));

    if (response.statusCode == 200) {
      return json.decode(response.body);
    } else if (response.statusCode == 404) {
      return json.decode(response.body);
    } else {
      throw Exception("Unsuccessful checking.");
    }
  }

  /// Fetches the election results
  ///
  /// @param from - String Voters account address
  /// @returns Response body
  Future<Map<String, dynamic>> getElectionResults() async {
    http.Response response =
        await http.get(Uri.http(blockchainServer, "/getResult"));

    if (response.statusCode == 200) {
      return json.decode(response.body);
    } else {
      throw Exception("Error in candidates");
    }
  }

  Future<Map<String, dynamic>> getMerkleTree() async {
    http.Response response =
        await http.get(Uri.http(blockchainServer, '/getMerkleTree'));
    if (response.statusCode == 200) {
      return json.decode(response.body);
    } else if (response.statusCode == 404) {
      return json.decode(response.body);
    } else {
      throw Exception("Unsuccessful get Merkle Tree.");
    }
  }

  Future<String> getMimcHash(String uid, String k) async {
    http.Response response = await http.post(Uri.http(plonkServer, '/mimc'),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(<String, dynamic>{
          'uid': uid,
          'k': k,
        }));
    if (response.statusCode == 200) {
      return json.decode(response.body)["hash"];
    } else {
      throw Exception("Unsuccessful hash calculating!");
    }
  }

  Future<Map<String, dynamic>> getPlonkProof(
      String uid, String k, int vote) async {
    Map<String, dynamic> merkleTree = await getMerkleTree();
    const requestInterval = Duration(seconds: 20);
    print(merkleTree["merkleTree"]);
    print("$uid, $k, $vote");
    http.Response response = await http.post(Uri.http(plonkServer, "/plonk"),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(<String, dynamic>{
          'uid': uid,
          'k': k,
          'vote': vote,
          'merkleTree': merkleTree['merkleTree']
        }));
    if (response.statusCode == 200) {
      final id = json.decode(response.body)['order'];
      while (true) {
        final response = await http.get(Uri.http(plonkServer, '/plonk/$id'));

        if (response.statusCode == 200) {
          final responseData = jsonDecode(response.body);
          // Check if the result is available
          if (responseData['msg'] == 'completed') {
            final result = json.decode(responseData['proof']);
            return result;
          }
        }
        // Wait for the specified interval before sending the next request
        await Future.delayed(requestInterval);
      }
    } else if (response.statusCode == 404) {
      return json.decode(response.body);
    } else {
      throw Exception("Unsuccessful proof calculating!");
    }
  }

  Future<Map<String, dynamic>> sendProof(proof) async {
    http.Response response = await http.post(Uri.http(blockchainServer, "/sendProof"),
        headers: {'Content-Type': 'application/json'},
        body: jsonEncode(<String, dynamic>{
          'proof': proof,
        }));
    if (response.statusCode == 200) {
      return json.decode(response.body);
    } else if (response.statusCode == 404) {
      return json.decode(response.body);
    } else {
      throw Exception("Unsuccessful proof calculating!");
    }
  }
}


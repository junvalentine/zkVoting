import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:mrtdeg/http/vote_http.dart';

class Vote extends StatefulWidget {
  Vote({required this.fullName, required this.id, required this.k});
  final String fullName;
  final String id;
  final String k;
  @override
  _VoteState createState() => _VoteState();
}

class _VoteState extends State<Vote> {
  int selectedCandidateIndex = -1;
  String selectedCandidate = "";
  VoteHttp voteHttp = VoteHttp();

  @override
  Widget build(BuildContext context) {
    return Scaffold(
        backgroundColor: Colors.white,
        body: Center(
          child: Column(
            mainAxisAlignment: MainAxisAlignment.spaceEvenly,
            children: <Widget>[
              Container(
                child: FutureBuilder<List<dynamic>>(
                    future: voteHttp.getCandidates(),
                    builder: (context, snapshot) {
                      if (snapshot.hasData) {
                        List<String> candidates = [];

                        for (var i = 0; i < snapshot.data!.length; i++) {
                          candidates.add(snapshot.data![i]);
                        }
                        // candidates = ['Ronaldo', 'Messi', 'Me'];
                        return ListView.builder(
                            scrollDirection: Axis.vertical,
                            shrinkWrap: true,
                            itemCount: candidates.length,
                            itemBuilder: (context, index) {
                              return Card(
                                  shape: RoundedRectangleBorder(
                                      borderRadius: BorderRadius.circular(15)),
                                  elevation: 5,
                                  margin:
                                      const EdgeInsets.fromLTRB(15, 30, 15, 0),
                                  color: selectedCandidateIndex == index
                                      ? Colors.blue
                                      : Colors.red,
                                  child: ListTile(
                                    leading: Icon(Icons.person),
                                    title: Text(
                                      candidates[index],
                                      style: TextStyle(
                                          fontSize: 24,
                                          color: Colors.white,
                                          fontWeight:
                                              selectedCandidateIndex == index
                                                  ? FontWeight.bold
                                                  : FontWeight.normal),
                                    ),
                                    onTap: () {
                                      setState(() {
                                        if (selectedCandidateIndex == index) {
                                          selectedCandidateIndex = -1;
                                          selectedCandidate = "Null";
                                        } else {
                                          selectedCandidateIndex = index;
                                          selectedCandidate = candidates[index];
                                        }
                                      });
                                    },
                                  ));
                            });
                      } else {
                        return Center();
                      }
                    }),
              ),
              SizedBox(
                height: 5,
              ),
              MaterialButton(
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(10)),
                height: 50,
                color: selectedCandidateIndex != -1
                    ? Colors.green
                    : Colors.black12,
                child: Text(
                  'Vote',
                  style: TextStyle(color: Colors.black87, fontSize: 20.0),
                ),
                onPressed: () async {
                  _showConfirmationDialog(
                      context, selectedCandidateIndex, selectedCandidate);
                },
              ),
            ],
          ),
        ));
  }

  _showConfirmationDialog(BuildContext context, int idx, String name) {
    showDialog(
      context: context,
      builder: (BuildContext context) {
        return AlertDialog(
          title: Text('Do vote',
              textAlign: TextAlign.center,
              style: TextStyle(fontWeight: FontWeight.bold)),
          content: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Center(
                child: Text(
                  'Do you really want to vote for:',
                  textAlign: TextAlign.center,
                ),
              ),
              Center(
                child: Text(
                  '[$selectedCandidateIndex. $selectedCandidate]?',
                  textAlign: TextAlign.center,
                ),
              ),
              SizedBox(height: 16),
              Center(
                child: Text(
                  'You CANNOT change it once you vote.',
                  style: TextStyle(color: Colors.red),
                  textAlign: TextAlign.center,
                ),
              ),
            ],
          ),
          actions: <Widget>[
            Row(
              children: [
                Expanded(
                  child: ElevatedButton(
                    style: ButtonStyle(
                      backgroundColor: MaterialStateProperty.all(Colors.grey),
                      shape: MaterialStateProperty.all(
                        RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(8),
                        ),
                      ),
                    ),
                    child: Text(
                      'Cancel',
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 16,
                      ),
                    ),
                    onPressed: () {
                      Navigator.of(context).pop();
                    },
                  ),
                ),
                SizedBox(width: 16),
                Expanded(
                  child: ElevatedButton(
                    style: ButtonStyle(
                      backgroundColor: MaterialStateProperty.all(Colors.blue),
                      shape: MaterialStateProperty.all(
                        RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(8),
                        ),
                      ),
                    ),
                    child: Text(
                      'Confirm',
                      style: TextStyle(
                        fontWeight: FontWeight.bold,
                        fontSize: 16,
                      ),
                    ),
                    onPressed: () async {
                      // Perform the vote action here
                      Navigator.of(context).pop();
                      if (selectedCandidateIndex != -1) {
                        Map<String, dynamic> proof =
                            await voteHttp.getPlonkProof(
                                widget.id, widget.k, selectedCandidateIndex);
                        Map<String, dynamic> msg =
                            await voteHttp.sendProof(proof);
                      }
                    },
                  ),
                ),
              ],
            )
          ],
        );
      },
    );
  }

  _showAlertDialog(BuildContext context, String title, String content) {
    showDialog(
        context: context,
        builder: (context) {
          return AlertDialog(
              title: Text(title, style: TextStyle(fontWeight: FontWeight.bold)),
              content: Text(
                content,
                style: TextStyle(fontSize: 20),
              ),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(10),
              ),
              actions: <Widget>[
                MaterialButton(
                    onPressed: () {
                      Navigator.pop(context);
                    },
                    child: Text(
                      "OK",
                      style:
                          TextStyle(fontSize: 20, fontWeight: FontWeight.bold),
                    ))
              ]);
        });
  }
}

import 'dart:typed_data';
import 'package:mrtdeg/http/vote_http.dart';
import 'package:flutter/material.dart';
import 'package:mrtdeg/mrtd.dart';
import 'package:mrtdeg/voting.dart';
import 'package:mrtdeg/info.dart';

class UserPage extends StatefulWidget {
  final MrtdData mrtdData;
  final String k;
  const UserPage({required this.mrtdData, required this.k});

  @override
  _UserPageState createState() => _UserPageState();
}

class _UserPageState extends State<UserPage> {
  int _currentIndex = 0;
  VoteHttp voteHttp = VoteHttp();
  @override
  Widget build(BuildContext context) {
    final userInformation = formatDG13(widget.mrtdData.dg13!);
    final facialImage = formatDG2(widget.mrtdData.dg2!);
    return Scaffold(
      appBar: AppBar(
        title: Text('User Page'),
        actions: [
          IconButton(
            icon: Icon(Icons.bar_chart),
            onPressed: () {
              voteHttp.getElectionResults().then((response) {
                if (response["status"] == "OK") {
                  String content = "";
                  for (int i = 0; i < response["candidates"].length; i++) {
                    content += response["candidates"][i] +
                        ": " +
                        response["voteCounts"][i].toString() +
                        "\n";
                  }
                  _showAlertDialog(context, "Election results", content);
                } else {
                  _showAlertDialog(
                      context, "Election results", response["reason"]);
                }
              });
            },
          )
        ],
      ),
      body: IndexedStack(
        index: _currentIndex,
        children: [
          Vote(
              fullName: userInformation["full name"],
              id: userInformation["document id"],
              k: widget.k),
          InfoWidget(
            information: userInformation,
            facialImage: facialImage,
          ),
        ],
      ),
      bottomNavigationBar: BottomNavigationBar(
        currentIndex: _currentIndex,
        onTap: (index) {
          setState(() {
            _currentIndex = index;
          });
        },
        items: [
          BottomNavigationBarItem(
            icon: Icon(Icons.how_to_vote),
            label: 'Vote',
          ),
          BottomNavigationBarItem(
            icon: Icon(Icons.info),
            label: 'Info',
          ),
        ],
      ),
    );
  }

  _showAlertDialog(BuildContext context, String title, String content) {
    return showDialog(
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

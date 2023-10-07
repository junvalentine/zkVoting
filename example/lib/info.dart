import 'package:flutter/material.dart';

class InfoWidget extends StatefulWidget {
  InfoWidget({required this.information, required this.facialImage});

  final Map information;
  final Image facialImage;
  @override
  _InfoWidgetState createState() => _InfoWidgetState();
}

class _InfoWidgetState extends State<InfoWidget> {
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Container(
        padding: EdgeInsets.all(16.0),
        child: SingleChildScrollView(
          child: Padding(
            padding: EdgeInsets.all(16.0),
            child: Column(
              // crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'ID Card',
                  textAlign: TextAlign.center,
                  style: TextStyle(
                    fontSize: 24,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                SizedBox(height: 16),
                CircleAvatar(
                  radius: 80,
                  backgroundImage: widget.facialImage.image,
                ),
                ListTile(
                  leading: Icon(Icons.credit_card),
                  title: Text(
                    'ID Number',
                    style: TextStyle(fontSize: 18),
                  ),
                  subtitle: Text(
                    widget.information["document id"],
                    style: TextStyle(fontSize: 14),
                  ),
                ),
                ListTile(
                  leading: Icon(Icons.date_range),
                  title: Text(
                    'Document Issue Date',
                    style: TextStyle(fontSize: 18),
                  ),
                  subtitle: Text(
                    widget.information['document issue date'],
                    style: TextStyle(fontSize: 14),
                  ),
                ),
                ListTile(
                  leading: Icon(Icons.date_range),
                  title: Text(
                    'Document Expiry Date',
                    style: TextStyle(fontSize: 18),
                  ),
                  subtitle: Text(
                    widget.information['document expiry date'],
                    style: TextStyle(fontSize: 14),
                  ),
                ),
                ListTile(
                  leading: Icon(Icons.person),
                  title: Text(
                    'Full Name',
                    style: TextStyle(fontSize: 18),
                  ),
                  subtitle: Text(
                    widget.information["full name"],
                    style: TextStyle(fontSize: 18),
                  ),
                ),
                ListTile(
                  leading: Icon(Icons.date_range),
                  title: Text(
                    'Birthday',
                    style: TextStyle(fontSize: 18),
                  ),
                  subtitle: Text(
                    widget.information["birthday"],
                    style: TextStyle(fontSize: 14),
                  ),
                ),
                ListTile(
                  leading: Icon(Icons.location_on),
                  title: Text(
                    'Nationality',
                    style: TextStyle(fontSize: 18),
                  ),
                  subtitle: Text(
                    widget.information["nationality"],
                    style: TextStyle(fontSize: 14),
                  ),
                ),
                ListTile(
                  leading: Icon(Icons.location_on),
                  title: Text(
                    'Address',
                    style: TextStyle(fontSize: 18),
                  ),
                  subtitle: Text(
                    widget.information['permanant address'],
                    style: TextStyle(fontSize: 14),
                  ),
                ),
                ListTile(
                  leading: Icon(Icons.person_outline),
                  title: Text(
                    'Belief',
                    style: TextStyle(fontSize: 18),
                  ),
                  subtitle: Text(
                    widget.information['belief'],
                    style: TextStyle(fontSize: 14),
                  ),
                ),
                ListTile(
                  leading: Icon(Icons.people_alt),
                  title: Text(
                    'Ethnicity',
                    style: TextStyle(fontSize: 18),
                  ),
                  subtitle: Text(
                    widget.information['ethnicity'],
                    style: TextStyle(fontSize: 14),
                  ),
                ),
                ListTile(
                  leading: Icon(Icons.face),
                  title: Text(
                    'Identify Features',
                    style: TextStyle(fontSize: 18),
                  ),
                  subtitle: Text(
                    widget.information['identify features'],
                    style: TextStyle(fontSize: 14),
                  ),
                ),
                ListTile(
                  leading: Icon(Icons.person),
                  title: Text(
                    'Father',
                    style: TextStyle(fontSize: 18),
                  ),
                  subtitle: Text(
                    widget.information['parent 1'],
                    style: TextStyle(fontSize: 14),
                  ),
                ),
                ListTile(
                  leading: Icon(Icons.person),
                  title: Text(
                    'Mother',
                    style: TextStyle(fontSize: 18),
                  ),
                  subtitle: Text(
                    widget.information['parent 2'],
                    style: TextStyle(fontSize: 14),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }


}
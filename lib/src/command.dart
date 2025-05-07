import 'dart:convert';
import 'dart:typed_data';

import 'package:id1_client/src/key.dart';

enum Op { list, get, set, add, mov, del, unknown }

class Id1Command {
  Op op;
  Id1Key key;
  Map<String, String>? args;
  Uint8List? data;

  Id1Command({required this.op, required this.key, this.args = const {}, this.data});

  @override
  String toString() {
    var uri = Uri(queryParameters: args == null || args!.isEmpty ? null : args);
    return "${op.name}:/${key.toString()}${uri.query.isEmpty ? "" : "?"}${uri.query}";
  }

  Uint8List toBytes() {
    List<int> bytes = [];
    bytes.addAll(Utf8Encoder().convert(toString()));
    if (data != null && data!.isNotEmpty) {
      bytes.add(10);
      bytes.addAll(data!);
    }
    bytes.add(10);
    return Uint8List.fromList(bytes);
  }
}

Id1Command parseId1Command(Uint8List data) {
  var cmdLineEnd = data.indexOf("\n".codeUnits.first);
  if (cmdLineEnd < 0) {
    cmdLineEnd = data.length;
  }
  var cmdLine = data.getRange(0, cmdLineEnd);
  Uint8List cmdData =
      data.length > cmdLineEnd
          ? Uint8List.fromList(data.getRange(cmdLineEnd + 1, data.length).toList())
          : Uint8List.fromList([]);

  var uri = Uri.parse(String.fromCharCodes(cmdLine));
  var op = Op.values.firstWhere((e) => e.toString() == "Op.${uri.scheme}");
  var key = Uri.decodeComponent(uri.path);
  if (key.startsWith("/")) key = key.substring(1);
  Map<String, String> args = uri.queryParameters;
  var cmd = Id1Command(op: op, key: Id1Key(key), args: args, data: cmdData);
  return cmd;
}

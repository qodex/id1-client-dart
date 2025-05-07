import 'dart:typed_data';

import 'package:id1_client/src/command.dart';
import 'package:id1_client/src/key.dart';
import 'package:id1_client/src/list_options.dart';

abstract class Id1Client {
  Future authenticate(String? id, String? privateKey);
  base(String base);
  Future connect();
  close();
  String addListener(Function(Id1Command cmd) listener, {String? listenerId});
  removeListener(String listenerId);
  send(Id1Command command);
  Future<Map<String, Uint8List>> list(Id1Key key, ListOptions opt);
  Future<Uint8List?> get(Id1Key key);
  Future<void> set(Id1Key key, Uint8List data);
  Future<void> add(Id1Key key, Uint8List data);
  Future<void> mov(Id1Key key, Id1Key tgtKey);
  Future<void> del(Id1Key key);
}

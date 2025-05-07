import 'dart:convert';
import 'dart:io';
import 'dart:isolate';
import 'dart:typed_data';

import 'package:id1_client/src/command.dart';
import 'package:id1_client/src/id1_client_http.dart';
import 'package:id1_client/src/key.dart';
import 'package:id1_client/src/list_options.dart';
import 'package:id1_client/src/rsa.dart';

const apiUrl = "http://localhost:8080";

void main() {
  for (var i = 0; i < 100; i++) {
    Isolate.run(() => crud("testid$i"));
    sleep(Duration(milliseconds: 10));
  }
}

crud(String id) async {
  var id1 = Id1ClientHttp(apiUrl: apiUrl);

  var kpair = RSA.generateKeyPair();
  var pubPEM = RSA.encodePublicKeyToPEM(kpair.publicKey);
  var prvPEM = RSA.encodePrivateKeyToPEM(kpair.privateKey);

  try {
    await id1.set(Id1Key("$id/pub/key"), Utf8Encoder().convert(pubPEM));
    print("created id: $id");
  } catch (e) {
    print("api error: $e");
    return;
  }

  if (!(await id1.authenticate(id, prvPEM))) {
    print("failed to authenticate");
    return;
  }

  await id1.set(Id1Key("$id/test/val"), utf8.encode(id));
  await id1.mov(Id1Key("$id/test/val"), Id1Key("$id/test/tres"));

  if (!(await id1.connect())) {
    print("failed to connect");
    return;
  }

  id1.addListener((cmd) => print("cmd in: ${utf8.decode(cmd.toBytes())}"));

  await Future.delayed(Duration(seconds: 1));

  var cmd = Id1Command(
    op: Op.set,
    key: Id1Key("$id/test/one"),
    args: {"ttl": "3"},
    data: Uint8List.fromList("Uno".codeUnits),
  );

  id1.send(cmd);

  await Future.delayed(Duration(seconds: 1));

  id1.send(Id1Command(op: Op.set, key: Id1Key("$id/test/two"), data: Uint8List.fromList("Dos".codeUnits)));

  await Future.delayed(Duration(seconds: 1));

  id1.send(Id1Command(op: Op.list, key: Id1Key("$id/test"), args: ListOptions(children: true).toMap()));

  await Future.delayed(Duration(seconds: 10));

  await id1.del(Id1Key(id));
  id1.close();
}

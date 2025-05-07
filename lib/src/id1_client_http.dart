import 'dart:convert';
import 'dart:typed_data';

import 'package:id1_client/id1_client.dart';
import 'package:logging/logging.dart';
import 'package:http/http.dart' as http;
import 'package:websocket_universal/websocket_universal.dart';
import 'package:uuid/uuid.dart';
import 'package:dart_jsonwebtoken/dart_jsonwebtoken.dart';

class Id1ClientHttp implements Id1Client {
  final logger = Logger("Id1ClientHttp");
  String apiUrl;
  String _id = "";
  String _base = "";
  String? token;
  Map<String, String> _headers = {};
  IWebSocketHandler<List<int>, List<int>>? _socketHandler;

  final Map<String, Function(Id1Command event)> _listeners = {};

  Id1ClientHttp({required this.apiUrl, this.token}) {
    if (token != null) {
      _headers = {"Authorization": token!};
    }
  }

  @override
  base(String base) {
    _base = base;
  }

  Uri _toUri(Id1Key key, Map<String, String>? args) {
    if (apiUrl.isEmpty) throw "invalid api url";
    if (!apiUrl.endsWith("/")) apiUrl = "$apiUrl/";
    if (_base.isNotEmpty && !_base.endsWith("/")) _base = "$_base/";
    var url = Uri.parse("$apiUrl$_base$key");
    return Uri(scheme: url.scheme, host: url.host, port: url.port, path: url.path, queryParameters: args);
  }

  @override
  String addListener(void Function(Id1Command cmd) listener, {String? listenerId}) {
    listenerId = listenerId ?? const Uuid().v4();
    _listeners[listenerId] = listener;
    return listenerId;
  }

  @override
  removeListener(String listenerId) {
    _listeners.remove(listenerId);
  }

  _notifyListeners(Id1Command cmd) async {
    for (var entry in _listeners.entries) {
      entry.value(cmd);
    }
  }

  @override
  Future authenticate(String? id, String? privateKey) async {
    if (id == null || privateKey == null) {
      return false;
    }
    try {
      final resp = await http.get(_toUri(Id1Key("$id/auth"), {}));
      Uint8List? challenge;
      try {
        challenge = base64.decode(resp.body.trim());
      } catch (e) {
        logger.fine("error decoding challenge: $e");
      }
      var secret = RSA.decrypt(challenge!, RSA.parsePrivateKeyPEM(privateKey));
      var secretString = Utf8Decoder(allowMalformed: true).convert(secret);
      // manchmal geht die uhr auf dem handy vor und dies führt dazu, dass die validierung fehlschlägt
      var iat = DateTime.now().subtract(const Duration(minutes: 5)).millisecondsSinceEpoch ~/ 1000;
      var jwt = JWT({"sub": id, "iat": iat}, issuer: 'https://id1.au').sign(SecretKey(secretString), noIssueAt: true);
      _headers = {"Authorization": "Bearer $jwt"};
      _id = id;
      return true;
    } catch (e) {
      logger.fine("error authenticating: $e");
      return false;
    }
  }

  @override
  Future<Map<String, Uint8List>> list(Id1Key key, ListOptions opt) async {
    key.segments.add("*");
    var resp = await http.get(_toUri(key, opt.toMap()), headers: _headers);
    switch (resp.statusCode) {
      case 200:
        throw "not implemented";
      case 404:
        return {};
      case 403:
        throw "forbidden";
      case 401:
        throw "bad token";
      default:
        throw "http error ${resp.statusCode}";
    }
  }

  @override
  Future<Uint8List?> get(Id1Key key) async {
    var resp = await http.get(_toUri(key, {}), headers: _headers);
    switch (resp.statusCode) {
      case 200:
        return resp.bodyBytes;
      case 404:
        return null;
      case 403:
        throw "forbidden";
      case 401:
        throw "bad auth token";
      default:
        throw "http error ${resp.statusCode}";
    }
  }

  @override
  Future set(Id1Key key, Uint8List value) async {
    var resp = await http.post(_toUri(key, {}), headers: _headers, body: value);
    switch (resp.statusCode) {
      case 403:
        throw "forbidden";
      case 401:
        throw "bad token";
    }
  }

  @override
  Future add(Id1Key key, Uint8List value) async {
    var resp = await http.patch(_toUri(key, {}), headers: _headers, body: value);
    switch (resp.statusCode) {
      case 403:
        throw "forbidden";
      case 401:
        throw "bad token";
    }
  }

  @override
  Future del(Id1Key key) async {
    var resp = await http.delete(_toUri(key, {}), headers: _headers);
    switch (resp.statusCode) {
      case 403:
        throw "forbidden";
      case 401:
        throw "bad token";
    }
  }

  @override
  Future<void> mov(Id1Key key, Id1Key tgtKey) async {
    var resp = await http.patch(_toUri(key, {}), headers: {..._headers, "X-Move-To": tgtKey.toString()});
    if (resp.statusCode == 403) throw "forbidden";
    if (resp.statusCode == 400) throw resp.body;
    if (resp.statusCode != 200) {
      logger.fine("http error ${resp.statusCode}: ${resp.body}");
    }
  }

  @override
  close() {
    if (_socketHandler != null) {
      _socketHandler!.close();
    }
  }

  @override
  Future connect() async {
    Uri wsUri = Uri.parse("${apiUrl.replaceFirst("http", "ws")}$_id/ws");

    IMessageProcessor<List<int>, List<int>> bytesSocketProcessor = SocketSimpleBytesProcessor();
    _socketHandler = IWebSocketHandler<List<int>, List<int>>.createClient(
      wsUri.toString(),
      bytesSocketProcessor,
      connectionOptions: SocketConnectionOptions(skipPingMessages: true, pingRestrictionForce: true),
    );

    _socketHandler!.incomingMessagesStream.listen((data) {
      try {
        var cmd = parseId1Command(Uint8List.fromList(data));
        _notifyListeners(cmd);
      } catch (e) {
        logger.fine("error pasing cmd: $e");
      }
    });

    await _socketHandler!.connect(params: SocketOptionalParams(headers: _headers));
    return true;
  }

  @override
  send(Id1Command cmd) {
    if (_socketHandler != null) {
      _socketHandler!.sendMessage(cmd.toBytes());
      return true;
    }
  }
}

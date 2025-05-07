import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';
import "package:pointycastle/export.dart";
import "package:asn1lib/asn1lib.dart";

class RSA {
  static AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> generateKeyPair() {
    var keyParams = RSAKeyGeneratorParameters(BigInt.parse('65537'), 1024, 12);

    var secureRandom = FortunaRandom();
    var random = Random.secure();
    List<int> seeds = [];
    for (int i = 0; i < 32; i++) {
      seeds.add(random.nextInt(255));
    }
    secureRandom.seed(KeyParameter(Uint8List.fromList(seeds)));

    var rngParams = ParametersWithRandom(keyParams, secureRandom);
    var k = RSAKeyGenerator();
    k.init(rngParams);

    return k.generateKeyPair();
  }

  static Uint8List encrypt(String plaintext, RSAPublicKey publicKey) {
    var cipher = RSAEngine()..init(true, PublicKeyParameter<RSAPublicKey>(publicKey));
    return cipher.process(Uint8List.fromList(plaintext.codeUnits));
  }

  static Uint8List decrypt(Uint8List data, RSAPrivateKey privateKey) {
    var rsaEngine = RSAEngine();
    rsaEngine.init(false, PrivateKeyParameter<RSAPrivateKey>(privateKey));

    var out = Uint8List(128);
    for (var i = 0; i < out.length; i++) {
      out[i] = 0;
    }
    rsaEngine.processBlock(data, 0, data.length, out, 0);

    var rightPadding = out[out.length - 2] == 0;
    if (rightPadding) {
      out = out.sublist(0, out.indexOf(0));
    } else {
      out = out.sublist(out.indexOf(0) + 1);
      out = out.sublist(0, out.indexOf(0));
    }
    return out;
  }

  static RSAPublicKey parsePublicKeyPEM(pemString) {
    List<int> publicKeyDER = decodePEM(pemString);
    var asn1Parser = ASN1Parser(Uint8List.fromList(publicKeyDER));
    var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    var publicKeyBitString = topLevelSeq.elements[1];

    var publicKeyAsn = ASN1Parser(publicKeyBitString.contentBytes());
    ASN1Sequence publicKeySeq = ASN1Sequence.fromBytes(publicKeyAsn.nextObject().encodedBytes);
    var modulus = publicKeySeq.elements[0] as ASN1Integer;
    var exponent = publicKeySeq.elements[1] as ASN1Integer;

    RSAPublicKey rsaPublicKey = RSAPublicKey(modulus.valueAsBigInteger, exponent.valueAsBigInteger);

    return rsaPublicKey;
  }

  static RSAPrivateKey parsePrivateKeyPEM(pemString) {
    List<int> privateKeyDER = decodePEM(pemString);
    var asn1Parser = ASN1Parser(Uint8List.fromList(privateKeyDER));
    var topLevelSeq = asn1Parser.nextObject() as ASN1Sequence;
    var privateKey = topLevelSeq.elements[2];

    asn1Parser = ASN1Parser(privateKey.contentBytes());
    var pkSeq = asn1Parser.nextObject() as ASN1Sequence;

    var modulus = pkSeq.elements[1] as ASN1Integer;
    var privateExponent = pkSeq.elements[3] as ASN1Integer;
    var p = pkSeq.elements[4] as ASN1Integer;
    var q = pkSeq.elements[5] as ASN1Integer;

    RSAPrivateKey rsaPrivateKey = RSAPrivateKey(
      modulus.valueAsBigInteger,
      privateExponent.valueAsBigInteger,
      p.valueAsBigInteger,
      q.valueAsBigInteger,
    );

    return rsaPrivateKey;
  }

  static String encodePublicKeyToPEM(RSAPublicKey publicKey) {
    var algorithmSeq = ASN1Sequence();
    var algorithmAsn1Obj = ASN1Object.fromBytes(
      Uint8List.fromList([0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]),
    );
    var paramsAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
    algorithmSeq.add(algorithmAsn1Obj);
    algorithmSeq.add(paramsAsn1Obj);

    var publicKeySeq = ASN1Sequence();
    publicKeySeq.add(ASN1Integer(publicKey.modulus!));
    publicKeySeq.add(ASN1Integer(publicKey.exponent!));
    var publicKeySeqBitString = ASN1BitString(Uint8List.fromList(publicKeySeq.encodedBytes));

    var topLevelSeq = ASN1Sequence();
    topLevelSeq.add(algorithmSeq);
    topLevelSeq.add(publicKeySeqBitString);
    var dataBase64 = base64.encode(topLevelSeq.encodedBytes);

    return """-----BEGIN PUBLIC KEY-----\r\n$dataBase64\r\n-----END PUBLIC KEY-----""";
  }

  static String encodePrivateKeyToPEM(RSAPrivateKey privateKey) {
    var version = ASN1Integer(BigInt.from(0));

    var algorithmSeq = ASN1Sequence();
    var algorithmAsn1Obj = ASN1Object.fromBytes(
      Uint8List.fromList([0x6, 0x9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0xd, 0x1, 0x1, 0x1]),
    );
    var paramsAsn1Obj = ASN1Object.fromBytes(Uint8List.fromList([0x5, 0x0]));
    algorithmSeq.add(algorithmAsn1Obj);
    algorithmSeq.add(paramsAsn1Obj);

    var privateKeySeq = ASN1Sequence();
    var modulus = ASN1Integer(privateKey.n!);
    var publicExponent = ASN1Integer(BigInt.parse('65537'));
    var privateExponent = ASN1Integer(privateKey.d!);
    var p = ASN1Integer(privateKey.p!);
    var q = ASN1Integer(privateKey.q!);
    var dP = privateKey.d! % (privateKey.p! - BigInt.from(1));
    var exp1 = ASN1Integer(dP);
    var dQ = privateKey.d! % (privateKey.q! - BigInt.from(1));
    var exp2 = ASN1Integer(dQ);
    var iQ = privateKey.q!.modInverse(privateKey.p!);
    var co = ASN1Integer(iQ);

    privateKeySeq.add(version);
    privateKeySeq.add(modulus);
    privateKeySeq.add(publicExponent);
    privateKeySeq.add(privateExponent);
    privateKeySeq.add(p);
    privateKeySeq.add(q);
    privateKeySeq.add(exp1);
    privateKeySeq.add(exp2);
    privateKeySeq.add(co);
    var publicKeySeqOctetString = ASN1OctetString(Uint8List.fromList(privateKeySeq.encodedBytes));

    var topLevelSeq = ASN1Sequence();
    topLevelSeq.add(version);
    topLevelSeq.add(algorithmSeq);
    topLevelSeq.add(publicKeySeqOctetString);
    var dataBase64 = base64.encode(topLevelSeq.encodedBytes);

    return """-----BEGIN PRIVATE KEY-----\r\n$dataBase64\r\n-----END PRIVATE KEY-----""";
  }
}

List<int> decodePEM(String pem) {
  var startsWith = [
    "-----BEGIN PUBLIC KEY-----",
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN PGP PUBLIC KEY BLOCK-----\r\nVersion: React-Native-OpenPGP.js 0.1\r\nComment: http://openpgpjs.org\r\n\r\n",
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\r\nVersion: React-Native-OpenPGP.js 0.1\r\nComment: http://openpgpjs.org\r\n\r\n",
  ];
  var endsWith = [
    "-----END PUBLIC KEY-----",
    "-----END PRIVATE KEY-----",
    "-----END PGP PUBLIC KEY BLOCK-----",
    "-----END PGP PRIVATE KEY BLOCK-----",
  ];
  bool isOpenPgp = pem.contains('BEGIN PGP');

  for (var s in startsWith) {
    if (pem.startsWith(s)) {
      pem = pem.substring(s.length);
    }
  }

  for (var s in endsWith) {
    if (pem.endsWith(s)) {
      pem = pem.substring(0, pem.length - s.length);
    }
  }

  if (isOpenPgp) {
    var index = pem.indexOf('\r\n');
    pem = pem.substring(0, index);
  }

  pem = pem.replaceAll('\n', '');
  pem = pem.replaceAll('\r', '');

  return base64.decode(pem);
}

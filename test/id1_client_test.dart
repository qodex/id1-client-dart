import 'dart:convert';

import 'package:id1_client/src/key.dart';
import 'package:id1_client/src/rsa.dart';
import 'package:test/test.dart';

var fakepk =
    "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALeAzDnMCy8G4n6zB1VbwRz2vXO7jZn6btOyChpXrJqznyHGs8J4FSg2EWbPfzTIGleMHuPBfV/mcatkD0Va3aGa0k0sK+vpTVkxl4RFs9aMUgTTYFYrSn6pkoHKOk2/4tgyvxgz8l9iaqGFVuGqejXm9UXJ82ZpUgHrLXIm2fvFAgMBAAECgYA7WIkz6/x18gkQJsApZ+o1fsrYggCSmr568mp4CIDG6258kvGR5Bobjhjkohimrkxuod9fkzUD7dg3ML4LlQ5150KqabXQj+D9wpmTdbYdVzLsvWS9P4AEnuLI1QtHnExKlH630k+e+bVeFFn0Ys455vCzbNMVoOpj6J2ZMPHu5QJBAPGRag7wm6o/4wTGG5r+G4MrzLWMHCz9rNLRQtBHP6Ibnrg1eB8hURJeDtmEYMTnWuBASp6aY1wbCV/gv8aZhVcCQQDCd1P+Xmv+cGAWuQKKidNF7JgipHkizCwKez5TgkKHfSZQHWyEw+YvPYE4reKc/+0kRHSAdRzZ1VT0jlhD4NpDAkEAvC4oLZ031mdQRQ7CwHnFGujK3n5YEKBIui2z26Y1JuZXPW7BtZZxnlpRPRdHfvwvKdRLjMP+NOkG436kRmSfnwJAREblRLAeNq1570Bx9fZCKZDSMYeRyHfrFpsC3QslFLEKHKLYER0+2mM71YynvfvVZSBrzxZPVOQj+eFoeBygRQJBANe6x0ddXK8iJ65lOmiGAvW4mghHZEryxDyH5wc3C2dHIMZPFXO/B4JjUGq3IXNHTv34jewUVWRRIcxU+y4bdMU=";

void main() {
  group('id1 client tests', () {
    setUp(() {
      // Additional setup goes here.
    });

    test('RSA roundtrip', () {
      var secret = "ein Spatz in der hand ist besser als eine Anananas im Arsch";
      var kpair = RSA.generateKeyPair();
      var pubPem = RSA.encodePublicKeyToPEM(kpair.publicKey);
      var prvPem = RSA.encodePrivateKeyToPEM(kpair.privateKey);
      var enc = RSA.encrypt(secret, RSA.parsePublicKeyPEM(pubPem));
      var dec = utf8.decode(RSA.decrypt(enc, RSA.parsePrivateKeyPEM(prvPem)));
      expect(dec, secret);
    });

    test('RSA - left nil padded', () {
      var encB64 =
          "aevZivMEyYezaxswyo4cZuFe2IobP6Ba0R9Tm51mQ1NEclciuO4z5+27zF2cT6S+jW6TK7C5rhioSvqSV+f1a3XSfCyZZAtTc6n5TxoAa+hJauS1m3H6PSq9SNYahstQV/RRZt70jyu0Jj+GIr+Q49nw57xHIv6nYDIZVkhmpjk=";
      var enc = base64Decode(encB64);
      var dec = Utf8Decoder(
        allowMalformed: true,
      ).convert(RSA.decrypt(enc, RSA.parsePrivateKeyPEM("$keyPrefix\n$fakepk\n$keySuffix")));
      expect(dec, "/j0G7IInr7FusMKfbkW6Sy7mM7bLpcIK16u1V+uZRyE=");
    });

    test('Id1Key', () {
      var k = Id1Key("ein/zwei/drei");
      var name = k.name();
      expect(name, "drei");
      expect(k.parent().name(), "zwei");
    });
  });
}

var keyPrefix = "-----BEGIN PRIVATE KEY-----";
var keySuffix = "-----END PRIVATE KEY-----";

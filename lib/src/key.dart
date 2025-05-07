class Id1Key {
  List<String> segments = [];
  Id1Key(String val) {
    segments = val.split("/");
  }

  String name() {
    if (segments.isNotEmpty) {
      return segments[segments.length - 1];
    } else {
      return "";
    }
  }

  Id1Key parent() {
    if (segments.length > 1) {
      return Id1Key(segments[segments.length - 2]);
    } else {
      return Id1Key("");
    }
  }

  @override
  String toString() {
    return segments.join("/");
  }
}

class ListOptions {
  int? limit;
  int? sizeLimit;
  int? totalSizeLimit;
  bool? keys;
  bool? recursive;
  bool? children;

  ListOptions({int? limit, int? sizeLimit, int? totalSizeLimit, bool? keys, bool? recursive, bool? children});

  Map<String, String> toMap() {
    Map<String, String> map = {};
    if (limit != null) map["limit"] = "$limit";
    if (sizeLimit != null) map["size-limit"] = "$sizeLimit";
    if (totalSizeLimit != null) map["total-size-limit"] = "$totalSizeLimit";
    if (keys != null) map["keys"] = "$keys";
    if (recursive != null) map["recursive"] = "$recursive";
    if (children != null) map["children"] = "$children";
    return map;
  }
}

import 'dart:convert';

import 'package:shared_preferences/shared_preferences.dart';

class SettingsStore {
  static const _baseUrlKey = 'api_base_url';
  static const _urlHistoryKey = 'url_history';
  static const _emailHistoryKey = 'email_history';

  Future<String> loadBaseUrl() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString(_baseUrlKey) ?? 'http://10.0.2.2:8000';
  }

  Future<void> saveBaseUrl(String value) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString(_baseUrlKey, value);
  }

  Future<List<String>> loadUrlHistory() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getStringList(_urlHistoryKey) ?? <String>[];
  }

  Future<void> saveUrlToHistory(String value) async {
    final trimmed = value.trim();
    if (trimmed.isEmpty) return;

    final prefs = await SharedPreferences.getInstance();
    final current = prefs.getStringList(_urlHistoryKey) ?? <String>[];
    final next = <String>[trimmed, ...current.where((item) => item != trimmed)];
    await prefs.setStringList(_urlHistoryKey, next.take(12).toList());
  }

  Future<void> clearUrlHistory() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_urlHistoryKey);
  }

  Future<List<EmailHistoryEntry>> loadEmailHistory() async {
    final prefs = await SharedPreferences.getInstance();
    final raw = prefs.getStringList(_emailHistoryKey) ?? <String>[];
    return raw
        .map((item) {
          try {
            return EmailHistoryEntry.fromJson(jsonDecode(item) as Map<String, dynamic>);
          } catch (_) {
            return null;
          }
        })
        .whereType<EmailHistoryEntry>()
        .toList();
  }

  Future<void> saveEmailToHistory(EmailHistoryEntry entry) async {
    if (entry.label.trim().isEmpty) return;

    final prefs = await SharedPreferences.getInstance();
    final current = prefs.getStringList(_emailHistoryKey) ?? <String>[];
    final encoded = jsonEncode(entry.toJson());
    final next = <String>[
      encoded,
      ...current.where((item) {
        try {
          final decoded = EmailHistoryEntry.fromJson(jsonDecode(item) as Map<String, dynamic>);
          return decoded.label != entry.label;
        } catch (_) {
          return true;
        }
      }),
    ];
    await prefs.setStringList(_emailHistoryKey, next.take(12).toList());
  }

  Future<void> clearEmailHistory() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove(_emailHistoryKey);
  }
}

class EmailHistoryEntry {
  const EmailHistoryEntry({
    required this.displayName,
    required this.senderEmail,
    required this.subject,
    required this.buttonUrl,
  });

  final String displayName;
  final String senderEmail;
  final String subject;
  final String buttonUrl;

  String get label {
    if (senderEmail.isNotEmpty) return senderEmail;
    if (displayName.isNotEmpty) return displayName;
    return subject;
  }

  Map<String, dynamic> toJson() => {
        'display_name': displayName,
        'sender_email': senderEmail,
        'subject': subject,
        'button_url': buttonUrl,
      };

  static EmailHistoryEntry fromJson(Map<String, dynamic> json) {
    return EmailHistoryEntry(
      displayName: (json['display_name'] ?? '').toString(),
      senderEmail: (json['sender_email'] ?? '').toString(),
      subject: (json['subject'] ?? '').toString(),
      buttonUrl: (json['button_url'] ?? '').toString(),
    );
  }
}

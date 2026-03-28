import 'dart:convert';

import 'package:http/http.dart' as http;

import '../models/analysis_models.dart';

class ApiService {
  ApiService({required this.baseUrl});

  final String baseUrl;

  Uri _uri(String path) => Uri.parse('$baseUrl$path');

  Future<ApiHealth> health() async {
    final response = await http.get(_uri('/health'));
    if (response.statusCode >= 400) {
      throw Exception('Falha ao consultar healthcheck: ${response.statusCode}');
    }
    final data = jsonDecode(response.body) as Map<String, dynamic>;
    final baseline = data['baseline'] as Map<String, dynamic>? ?? {};
    return ApiHealth(
      status: (data['status'] ?? 'unknown').toString(),
      baselineDescription:
          'Baseline: ${baseline['features'] ?? '-'} features | threshold ${baseline['threshold'] ?? '-'}',
    );
  }

  Future<AnalysisEnvelope> analyzeUrl(String url) async {
    final response = await http.post(
      _uri('/analyze/url'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'url': url}),
    );
    if (response.statusCode >= 400) {
      throw Exception('Falha ao analisar URL: ${response.statusCode}');
    }
    final data = jsonDecode(response.body) as Map<String, dynamic>;
    return AnalysisEnvelope(
      input: Map<String, dynamic>.from(data['input'] as Map),
      result: Map<String, dynamic>.from(data['result'] as Map),
    );
  }

  Future<AnalysisEnvelope> analyzeEmail(Map<String, dynamic> payload) async {
    final response = await http.post(
      _uri('/analyze/email'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode(payload),
    );
    if (response.statusCode >= 400) {
      throw Exception('Falha ao analisar email: ${response.statusCode}');
    }
    final data = jsonDecode(response.body) as Map<String, dynamic>;
    return AnalysisEnvelope(
      input: Map<String, dynamic>.from(data['input'] as Map),
      result: Map<String, dynamic>.from(data['result'] as Map),
    );
  }
}

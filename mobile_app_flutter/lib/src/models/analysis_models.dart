import 'package:flutter/material.dart';

class ApiHealth {
  const ApiHealth({
    required this.status,
    required this.baselineDescription,
  });

  final String status;
  final String baselineDescription;
}

class AnalysisEnvelope {
  const AnalysisEnvelope({
    required this.input,
    required this.result,
  });

  final Map<String, dynamic> input;
  final Map<String, dynamic> result;
}

Color riskColor(String faixaRisco) {
  switch (faixaRisco) {
    case 'phishing':
      return const Color(0xFFB42318);
    case 'suspeito':
      return const Color(0xFFB54708);
    default:
      return const Color(0xFF027A48);
  }
}

Color riskTint(String faixaRisco) {
  switch (faixaRisco) {
    case 'phishing':
      return const Color(0xFFFEE4E2);
    case 'suspeito':
      return const Color(0xFFFFF1E6);
    default:
      return const Color(0xFFEAFBF2);
  }
}

String riskIcon(String faixaRisco) {
  switch (faixaRisco) {
    case 'phishing':
      return '⚠';
    case 'suspeito':
      return '!';
    default:
      return '✓';
  }
}

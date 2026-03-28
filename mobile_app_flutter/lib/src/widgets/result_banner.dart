import 'package:flutter/material.dart';

import '../models/analysis_models.dart';

class ResultBanner extends StatelessWidget {
  const ResultBanner({
    super.key,
    required this.faixaRisco,
    required this.label,
    required this.score,
  });

  final String faixaRisco;
  final String label;
  final double score;

  @override
  Widget build(BuildContext context) {
    final accent = riskColor(faixaRisco);
    final tint = riskTint(faixaRisco);

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: tint,
        borderRadius: BorderRadius.circular(22),
        border: Border.all(color: accent.withValues(alpha: 0.25)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            '${riskIcon(faixaRisco)} $label',
            style: TextStyle(
              color: accent,
              fontSize: 24,
              fontWeight: FontWeight.w800,
            ),
          ),
          const SizedBox(height: 10),
          Text(
            'Score de risco: ${(score * 100).toStringAsFixed(2)}%',
            style: TextStyle(
              color: accent,
              fontSize: 16,
              fontWeight: FontWeight.w700,
            ),
          ),
        ],
      ),
    );
  }
}

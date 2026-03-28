import 'package:flutter/material.dart';

import '../models/analysis_models.dart';
import '../services/api_service.dart';
import '../services/settings_store.dart';
import '../widgets/detail_section.dart';
import '../widgets/result_banner.dart';

class UrlAnalysisTab extends StatefulWidget {
  const UrlAnalysisTab({
    super.key,
    required this.apiService,
  });

  final ApiService apiService;

  @override
  State<UrlAnalysisTab> createState() => _UrlAnalysisTabState();
}

class _UrlAnalysisTabState extends State<UrlAnalysisTab> {
  final _controller = TextEditingController();
  final _settingsStore = SettingsStore();
  AnalysisEnvelope? _result;
  String? _error;
  bool _loading = false;
  List<String> _history = const [];

  @override
  void initState() {
    super.initState();
    _loadHistory();
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Future<void> _loadHistory() async {
    final history = await _settingsStore.loadUrlHistory();
    if (!mounted) return;
    setState(() => _history = history);
  }

  Future<void> _clearHistory() async {
    final confirmed = await showDialog<bool>(
          context: context,
          builder: (context) => AlertDialog(
            title: const Text('Limpar histórico'),
            content: const Text('Deseja remover todo o histórico de URLs deste aparelho?'),
            actions: [
              TextButton(
                onPressed: () => Navigator.of(context).pop(false),
                child: const Text('Cancelar'),
              ),
              FilledButton(
                onPressed: () => Navigator.of(context).pop(true),
                child: const Text('Limpar'),
              ),
            ],
          ),
        ) ??
        false;

    if (!confirmed) return;

    await _settingsStore.clearUrlHistory();
    if (!mounted) return;
    setState(() => _history = const []);
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Histórico de URL limpo.')),
    );
  }

  Future<void> _submit() async {
    final raw = _controller.text.trim();
    if (raw.isEmpty) {
      setState(() => _error = 'Digite uma URL para análise.');
      return;
    }

    final normalized = raw.startsWith('http://') || raw.startsWith('https://')
        ? raw
        : 'https://$raw';

    setState(() {
      _loading = true;
      _error = null;
      _result = null;
    });

    try {
      final result = await widget.apiService.analyzeUrl(normalized);
      await _settingsStore.saveUrlToHistory(normalized);
      if (!mounted) return;
      setState(() => _result = result);
      await _loadHistory();
    } catch (error) {
      if (!mounted) return;
      setState(() => _error = error.toString());
    } finally {
      if (mounted) {
        setState(() => _loading = false);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    final result = _result?.result;
    final reasons =
        ((result?['explicacao']?['principais_razoes'] as List?) ?? []).cast<dynamic>();

    return ListView(
      padding: const EdgeInsets.only(bottom: 40),
      children: [
        Card(
          child: Padding(
            padding: const EdgeInsets.all(18),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Análise de URL',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.w800),
                ),
                const SizedBox(height: 8),
                const Text(
                  'Cole um link para receber classificação em 3 níveis e as razões principais do risco.',
                  style: TextStyle(color: Color(0xFF486581), height: 1.4),
                ),
                const SizedBox(height: 16),
                TextField(
                  controller: _controller,
                  minLines: 1,
                  maxLines: 3,
                  textInputAction: TextInputAction.done,
                  decoration: const InputDecoration(
                    labelText: 'URL',
                    hintText: 'https://exemplo.com',
                  ),
                ),
                const SizedBox(height: 16),
                FilledButton(
                  onPressed: _loading ? null : _submit,
                  style: FilledButton.styleFrom(
                    minimumSize: const Size.fromHeight(52),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(18),
                    ),
                  ),
                  child: Text(_loading ? 'Analisando...' : 'Analisar URL'),
                ),
                if (_error != null) ...[
                  const SizedBox(height: 12),
                  Text(
                    _error!,
                    style: const TextStyle(
                      color: Color(0xFFB42318),
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                ],
              ],
            ),
          ),
        ),
        if (result != null) ...[
          const SizedBox(height: 16),
          ResultBanner(
            faixaRisco: (result['faixa_risco'] ?? 'legitimo').toString(),
            label: (result['faixa_risco_label'] ?? 'Sem classificação').toString(),
            score: ((result['prob_phishing'] ?? 0.0) as num).toDouble(),
          ),
          const SizedBox(height: 16),
          DetailSection(
            title: 'Resumo da análise',
            lines: [
              'Nível de risco: ${result['nivel_risco']}',
              'Modo usado: ${result['modo_final']}',
              'Fallback: ${result['usou_fallback'] == true ? 'sim' : 'não'}',
              'Probabilidade de phishing: ${(((result['prob_phishing'] ?? 0.0) as num).toDouble() * 100).toStringAsFixed(2)}%',
            ],
          ),
          const SizedBox(height: 16),
          DetailSection(
            title: 'Razões principais',
            lines: reasons.isEmpty
                ? const ['Nenhuma razão principal foi retornada.']
                : reasons.map((item) => '- $item').toList(),
          ),
        ],
        if (_history.isNotEmpty) ...[
          const SizedBox(height: 16),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(18),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Expanded(
                        child: Text(
                          'Histórico de URL',
                          style: TextStyle(fontSize: 18, fontWeight: FontWeight.w800),
                        ),
                      ),
                      TextButton(
                        onPressed: _clearHistory,
                        child: const Text('Limpar'),
                      ),
                    ],
                  ),
                  const SizedBox(height: 8),
                  const Text(
                    'Toque em um item para reutilizar a URL no campo acima.',
                    style: TextStyle(color: Color(0xFF486581), height: 1.4),
                  ),
                  const SizedBox(height: 12),
                  ..._history.map(
                    (item) => ListTile(
                      contentPadding: EdgeInsets.zero,
                      dense: true,
                      title: Text(
                        item,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                      onTap: () {
                        _controller.text = item;
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('URL carregada no campo de análise.')),
                        );
                      },
                    ),
                  ),
                ],
              ),
            ),
          ),
        ],
      ],
    );
  }
}

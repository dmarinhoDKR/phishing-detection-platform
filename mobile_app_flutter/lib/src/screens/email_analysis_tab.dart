import 'package:flutter/material.dart';

import '../models/analysis_models.dart';
import '../services/api_service.dart';
import '../services/settings_store.dart';
import '../widgets/detail_section.dart';
import '../widgets/result_banner.dart';

class EmailAnalysisTab extends StatefulWidget {
  const EmailAnalysisTab({
    super.key,
    required this.apiService,
  });

  final ApiService apiService;

  @override
  State<EmailAnalysisTab> createState() => _EmailAnalysisTabState();
}

class _EmailAnalysisTabState extends State<EmailAnalysisTab> {
  final _displayName = TextEditingController();
  final _senderEmail = TextEditingController();
  final _subject = TextEditingController();
  final _body = TextEditingController();
  final _buttonUrl = TextEditingController();
  final _headers = TextEditingController();
  final _settingsStore = SettingsStore();

  AnalysisEnvelope? _result;
  String? _error;
  bool _loading = false;
  bool _attachmentsBlocked = false;
  bool _markedAsJunk = false;
  bool _showAdvanced = false;
  List<EmailHistoryEntry> _history = const [];

  @override
  void initState() {
    super.initState();
    _loadHistory();
  }

  @override
  void dispose() {
    _displayName.dispose();
    _senderEmail.dispose();
    _subject.dispose();
    _body.dispose();
    _buttonUrl.dispose();
    _headers.dispose();
    super.dispose();
  }

  Future<void> _loadHistory() async {
    final history = await _settingsStore.loadEmailHistory();
    if (!mounted) return;
    setState(() => _history = history);
  }

  Future<void> _clearHistory() async {
    final confirmed = await showDialog<bool>(
          context: context,
          builder: (context) => AlertDialog(
            title: const Text('Limpar histórico'),
            content: const Text('Deseja remover todo o histórico de emails deste aparelho?'),
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

    await _settingsStore.clearEmailHistory();
    if (!mounted) return;
    setState(() => _history = const []);
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('Histórico de email limpo.')),
    );
  }

  Future<void> _submit() async {
    if (_displayName.text.trim().isEmpty &&
        _senderEmail.text.trim().isEmpty &&
        _subject.text.trim().isEmpty) {
      setState(() => _error = 'Preencha ao menos nome exibido, remetente ou assunto.');
      return;
    }

    setState(() {
      _loading = true;
      _error = null;
      _result = null;
    });

    try {
      final result = await widget.apiService.analyzeEmail({
        'display_name': _displayName.text.trim(),
        'sender_email': _senderEmail.text.trim(),
        'subject': _subject.text.trim(),
        'body_excerpt': _showAdvanced ? _body.text.trim() : '',
        'button_url': _buttonUrl.text.trim(),
        'raw_headers': _showAdvanced ? _headers.text.trim() : '',
        'attachments_blocked': _showAdvanced ? _attachmentsBlocked : false,
        'marked_as_junk': _showAdvanced ? _markedAsJunk : false,
      });
      await _settingsStore.saveEmailToHistory(
        EmailHistoryEntry(
          displayName: _displayName.text.trim(),
          senderEmail: _senderEmail.text.trim(),
          subject: _subject.text.trim(),
          buttonUrl: _buttonUrl.text.trim(),
        ),
      );
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

  Widget _buildField(TextEditingController controller, String label, {int maxLines = 1}) {
    return TextField(
      controller: controller,
      maxLines: maxLines,
      decoration: InputDecoration(labelText: label),
    );
  }

  @override
  Widget build(BuildContext context) {
    final result = _result?.result;
    final reasons = ((result?['reasons'] as List?) ?? []).cast<dynamic>();
    final trustSignals = ((result?['trust_signals'] as List?) ?? []).cast<dynamic>();
    final headerAnalysis = result?['header_analysis'] as Map<String, dynamic>?;

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
                  'Análise de Email',
                  style: TextStyle(fontSize: 18, fontWeight: FontWeight.w800),
                ),
                const SizedBox(height: 8),
                const Text(
                  'Ideal para casos em que o golpe está mais no remetente, no contexto do email ou nos cabeçalhos.',
                  style: TextStyle(color: Color(0xFF486581), height: 1.4),
                ),
                const SizedBox(height: 8),
                const Text(
                  'Campos essenciais: nome exibido, remetente, assunto e link principal.',
                  style: TextStyle(color: Color(0xFF486581), height: 1.4, fontWeight: FontWeight.w600),
                ),
                const SizedBox(height: 4),
                const Text(
                  'Campos avançados: corpo, cabeçalhos e sinais extras entram como reforço opcional.',
                  style: TextStyle(color: Color(0xFF486581), height: 1.4),
                ),
                const SizedBox(height: 16),
                _buildField(_displayName, 'Nome exibido do remetente'),
                const SizedBox(height: 12),
                _buildField(_senderEmail, 'Email do remetente'),
                const SizedBox(height: 12),
                _buildField(_subject, 'Assunto'),
                const SizedBox(height: 12),
                _buildField(_buttonUrl, 'URL do botão ou link principal'),
                const SizedBox(height: 12),
                SwitchListTile(
                  value: _showAdvanced,
                  onChanged: (value) => setState(() => _showAdvanced = value),
                  contentPadding: EdgeInsets.zero,
                  title: Text(_showAdvanced ? 'Ocultar análise avançada' : 'Mostrar análise avançada (reforço opcional)'),
                ),
                if (_showAdvanced) ...[
                  const SizedBox(height: 4),
                  _buildField(_body, 'Trecho do corpo do email', maxLines: 4),
                  const SizedBox(height: 12),
                  _buildField(_headers, 'Cabeçalhos brutos do email', maxLines: 5),
                  const SizedBox(height: 12),
                  SwitchListTile(
                    value: _attachmentsBlocked,
                    onChanged: (value) => setState(() => _attachmentsBlocked = value),
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Anexos bloqueados pelo provedor'),
                  ),
                  SwitchListTile(
                    value: _markedAsJunk,
                    onChanged: (value) => setState(() => _markedAsJunk = value),
                    contentPadding: EdgeInsets.zero,
                    title: const Text('Mensagem marcada como lixo eletrônico'),
                  ),
                ],
                const SizedBox(height: 8),
                FilledButton(
                  onPressed: _loading ? null : _submit,
                  style: FilledButton.styleFrom(
                    minimumSize: const Size.fromHeight(52),
                    shape: RoundedRectangleBorder(
                      borderRadius: BorderRadius.circular(18),
                    ),
                  ),
                  child: Text(_loading ? 'Analisando...' : 'Analisar Email'),
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
            score: ((result['score_email'] ?? 0.0) as num).toDouble(),
          ),
          const SizedBox(height: 16),
          DetailSection(
            title: 'Resumo do email',
            lines: [
              'Marca alegada: ${result['claimed_brand'] ?? 'não identificada'}',
              'Domínio do remetente: ${result['sender_domain'] ?? 'não identificado'}',
              'Nível de risco: ${result['nivel_risco']}',
              'Score do email: ${(((result['score_email'] ?? 0.0) as num).toDouble() * 100).toStringAsFixed(2)}%',
            ],
          ),
          const SizedBox(height: 16),
          DetailSection(
            title: 'Sinais encontrados',
            lines: reasons.isEmpty
                ? const ['Nenhum sinal principal foi retornado.']
                : reasons.map((item) => '- $item').toList(),
          ),
          if (trustSignals.isNotEmpty) ...[
            const SizedBox(height: 16),
            DetailSection(
              title: 'Sinais de confiança',
              lines: trustSignals.map((item) => '- $item').toList(),
            ),
          ],
          if (headerAnalysis != null) ...[
            const SizedBox(height: 16),
            DetailSection(
              title: 'Análise de cabeçalhos',
              lines: [
                'Score dos cabeçalhos: ${((((headerAnalysis['score'] ?? 0.0) as num).toDouble()) * 100).toStringAsFixed(2)}%',
                ...(((headerAnalysis['findings'] as List?) ?? []).map((item) => '- $item')),
              ],
            ),
          ],
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
                          'Histórico de Email',
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
                    'Toque em um item para reutilizar como remetente ou referência rápida.',
                    style: TextStyle(color: Color(0xFF486581), height: 1.4),
                  ),
                  const SizedBox(height: 12),
                  ..._history.map(
                    (item) => ListTile(
                      contentPadding: EdgeInsets.zero,
                      dense: true,
                      title: Text(
                        item.label,
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                      subtitle: item.subject.isNotEmpty
                          ? Text(
                              item.subject,
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            )
                          : null,
                      onTap: () {
                        _displayName.text = item.displayName;
                        _senderEmail.text = item.senderEmail;
                        _subject.text = item.subject;
                        _buttonUrl.text = item.buttonUrl;
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('Email carregado para reutilização.')),
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

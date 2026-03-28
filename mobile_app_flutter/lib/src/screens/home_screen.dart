import 'package:flutter/material.dart';

import '../models/analysis_models.dart';
import '../services/api_service.dart';
import '../services/settings_store.dart';
import 'email_analysis_tab.dart';
import 'url_analysis_tab.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});

  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabController;
  final _settingsStore = SettingsStore();

  String? _baseUrl;
  ApiHealth? _health;
  bool _loadingHealth = true;
  String? _healthError;

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _bootstrap();
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _bootstrap() async {
    final baseUrl = await _settingsStore.loadBaseUrl();
    if (!mounted) return;
    setState(() => _baseUrl = baseUrl);
    await _refreshHealth();
  }

  Future<void> _refreshHealth() async {
    final baseUrl = _baseUrl;
    if (baseUrl == null) return;

    setState(() {
      _loadingHealth = true;
      _healthError = null;
    });

    try {
      final api = ApiService(baseUrl: baseUrl);
      final health = await api.health();
      if (!mounted) return;
      setState(() => _health = health);
    } catch (error) {
      if (!mounted) return;
      setState(() => _healthError = error.toString());
    } finally {
      if (mounted) {
        setState(() => _loadingHealth = false);
      }
    }
  }

  Future<void> _openApiSettings() async {
    final controller = TextEditingController(text: _baseUrl ?? '');

    final saved = await showModalBottomSheet<bool>(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (context) {
        return Padding(
          padding: EdgeInsets.only(
            left: 16,
            right: 16,
            top: 16,
            bottom: MediaQuery.of(context).viewInsets.bottom + 16,
          ),
          child: Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: Colors.white,
              borderRadius: BorderRadius.circular(28),
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Text(
                  'Configurar API',
                  style: TextStyle(fontSize: 20, fontWeight: FontWeight.w800),
                ),
                const SizedBox(height: 8),
                const Text(
                  'Use 10.0.2.2 no Android Emulator, 127.0.0.1 no iPhone Simulator e o IP local da máquina em aparelho físico.',
                  style: TextStyle(color: Color(0xFF486581), height: 1.45),
                ),
                const SizedBox(height: 16),
                TextField(
                  controller: controller,
                  decoration: const InputDecoration(
                    labelText: 'Base URL da API',
                    hintText: 'http://10.0.2.2:8000',
                  ),
                ),
                const SizedBox(height: 16),
                FilledButton(
                  onPressed: () => Navigator.of(context).pop(true),
                  style: FilledButton.styleFrom(
                    minimumSize: const Size.fromHeight(52),
                  ),
                  child: const Text('Salvar e testar'),
                ),
              ],
            ),
          ),
        );
      },
    );

    if (saved == true) {
      final newValue = controller.text.trim();
      if (newValue.isNotEmpty) {
        await _settingsStore.saveBaseUrl(newValue);
        if (!mounted) return;
        setState(() => _baseUrl = newValue);
        await _refreshHealth();
      }
    }
  }

  Widget _buildHealthCard() {
    final healthy = _health?.status == 'ok' && _healthError == null;
    final accent = healthy ? const Color(0xFF027A48) : const Color(0xFFB42318);
    final tint = healthy ? const Color(0xFFEAFBF2) : const Color(0xFFFEE4E2);

    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: tint,
        borderRadius: BorderRadius.circular(22),
        border: Border.all(color: accent.withValues(alpha: 0.18)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                width: 10,
                height: 10,
                decoration: BoxDecoration(
                  color: accent,
                  shape: BoxShape.circle,
                ),
              ),
              const SizedBox(width: 10),
              Text(
                _loadingHealth ? 'Verificando API...' : (healthy ? 'API online' : 'API indisponível'),
                style: TextStyle(
                  color: accent,
                  fontWeight: FontWeight.w800,
                  fontSize: 16,
                ),
              ),
              const Spacer(),
              TextButton(
                onPressed: _refreshHealth,
                child: const Text('Atualizar'),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            _baseUrl ?? 'Sem URL configurada',
            style: const TextStyle(
              color: Color(0xFF243B53),
              fontWeight: FontWeight.w700,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            _healthError ?? (_health?.baselineDescription ?? 'Sem informações do baseline.'),
            style: const TextStyle(color: Color(0xFF486581), height: 1.4),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final baseUrl = _baseUrl ?? 'http://10.0.2.2:8000';
    final apiService = ApiService(baseUrl: baseUrl);

    return Scaffold(
      body: SafeArea(
        child: NestedScrollView(
          headerSliverBuilder: (context, innerBoxIsScrolled) {
            return [
              SliverToBoxAdapter(
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(20, 18, 20, 8),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          const Expanded(
                            child: Column(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Text(
                                  'Detector de Phishing',
                                  style: TextStyle(
                                    fontSize: 28,
                                    fontWeight: FontWeight.w900,
                                    color: Color(0xFF102A43),
                                  ),
                                ),
                                SizedBox(height: 6),
                                Text(
                                  'Análise mobile com foco em risco claro, explicação útil e resposta rápida.',
                                  style: TextStyle(
                                    color: Color(0xFF486581),
                                    height: 1.45,
                                  ),
                                ),
                              ],
                            ),
                          ),
                          IconButton.filledTonal(
                            onPressed: _openApiSettings,
                            icon: const Icon(Icons.tune_rounded),
                          ),
                        ],
                      ),
                      const SizedBox(height: 18),
                      _buildHealthCard(),
                      const SizedBox(height: 18),
                    ],
                  ),
                ),
              ),
              SliverPersistentHeader(
                pinned: true,
                delegate: _TabHeaderDelegate(
                  TabBar(
                    controller: _tabController,
                    indicatorSize: TabBarIndicatorSize.tab,
                    dividerColor: Colors.transparent,
                    padding: const EdgeInsets.symmetric(horizontal: 20),
                    tabs: const [
                      Tab(text: 'URL'),
                      Tab(text: 'Email'),
                    ],
                  ),
                ),
              ),
            ];
          },
          body: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 20),
            child: TabBarView(
              controller: _tabController,
              children: [
                UrlAnalysisTab(apiService: apiService),
                EmailAnalysisTab(apiService: apiService),
              ],
            ),
          ),
        ),
      ),
    );
  }
}

class _TabHeaderDelegate extends SliverPersistentHeaderDelegate {
  const _TabHeaderDelegate(this.child);

  final PreferredSizeWidget child;

  @override
  double get minExtent => child.preferredSize.height + 12;

  @override
  double get maxExtent => child.preferredSize.height + 12;

  @override
  Widget build(BuildContext context, double shrinkOffset, bool overlapsContent) {
    return Container(
      color: const Color(0xFFF3F7FB),
      padding: const EdgeInsets.only(bottom: 12),
      child: child,
    );
  }

  @override
  bool shouldRebuild(covariant SliverPersistentHeaderDelegate oldDelegate) => false;
}

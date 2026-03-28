import 'package:flutter_test/flutter_test.dart';
import 'package:shared_preferences/shared_preferences.dart';

import 'package:phishing_ai_mobile/src/app.dart';

void main() {
  testWidgets('renderiza a estrutura principal do app', (WidgetTester tester) async {
    SharedPreferences.setMockInitialValues(const {
      'api_base_url': 'http://10.0.2.2:8000',
    });

    await tester.pumpWidget(const PhishingAiMobileApp());
    await tester.pumpAndSettle();

    expect(find.text('Detector de Phishing'), findsOneWidget);
    expect(find.text('URL'), findsWidgets);
    expect(find.text('Email'), findsWidgets);
  });
}

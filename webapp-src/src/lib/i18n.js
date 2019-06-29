import i18n from 'i18next';
import Backend from 'i18next-xhr-backend';
import LanguageDetector from 'i18next-browser-languagedetector';
import { reactI18nextModule } from 'react-i18next';

i18n
	.use(Backend)
	.use(LanguageDetector)
	.use(reactI18nextModule)
	.init({
		fallbackLng: 'en',

		// have a common namespace used around the full app
		ns: ['translations'],
		defaultNS: 'translations',

		interpolation: {
			escapeValue: false, // not needed for react!!
		},

		react: {
			wait: true
		},
		
		backend: {
			loadPath: 'locales/{{lng}}/{{ns}}.json'
		}
	});


export default i18n;

import { useState } from 'react';
import { ShieldAlert } from 'lucide-react';
import { useTranslation } from 'react-i18next';

interface Props {
  onAccept: () => void;
}

export default function ConsentScreen({ onAccept }: Props) {
  const { t } = useTranslation();
  const [accepted, setAccepted] = useState(false);

  const handleAccept = () => {
    setAccepted(true);
    // Log to audit would go here
    setTimeout(onAccept, 500);
  };

  return (
    <div className="fixed inset-0 bg-black z-[9999] flex items-center justify-center p-8">
      <div className={`max-w-2xl bg-gray-900 border-2 border-red-600 p-8 rounded-lg transition-opacity duration-500 ${accepted ? 'opacity-0' : 'opacity-100'}`}>
        <div className="flex items-center justify-center mb-6 text-red-500">
          <ShieldAlert size={64} />
        </div>
        <h1 className="text-2xl font-bold text-center text-white mb-6 uppercase">
          {t('consent_title')}
        </h1>
        <div className="text-gray-300 space-y-4 text-sm font-mono leading-relaxed mb-8">
          <p>You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only.</p>
          <p>By using this IS (which includes any device attached to this IS), you consent to the following conditions:</p>
          <ul className="list-disc pl-6 space-y-2">
            <li>The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations.</li>
            <li>At any time, the USG may inspect and seize data stored on this IS.</li>
            <li>Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose.</li>
          </ul>
        </div>
        <div className="flex justify-center">
          <button 
            onClick={handleAccept}
            className="px-8 py-3 bg-red-600 hover:bg-red-700 text-white font-bold rounded uppercase tracking-wider"
          >
            {t('accept')}
          </button>
        </div>
      </div>
    </div>
  );
}

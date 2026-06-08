import { useState } from 'react';

interface AIAnalysisPanelProps {
  scanData: any;
  gitData: any | null;
  pryResults: any[] | null;
}

export function AIAnalysisPanel({ scanData, gitData, pryResults }: AIAnalysisPanelProps) {
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const runEngine = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await fetch('http://127.0.0.1:8000/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          social: scanData,
          github: gitData,
          deepPry: pryResults
        }),
      });

      if (!response.ok) {
        throw new Error(`Engine responded with status code ${response.status}`);
      }

      const data = await response.json();
      setReport(data.analysis);
    } catch (err: any) {
      setError(err.message || 'Cognitive pipeline execution failure.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
      <div>
        <button
          onClick={runEngine}
          disabled={loading}
          style={{
            background: loading ? '#222' : '#00ff66',
            color: loading ? '#555' : '#000',
            border: 'none',
            padding: '0.6rem 1.5rem',
            cursor: loading ? 'not-allowed' : 'pointer',
            fontWeight: 'bold',
            fontFamily: 'monospace',
            fontSize: '0.75rem',
            letterSpacing: '0.05em'
          }}
        >
          {loading ? 'PROCESSING...' : 'EXECUTE AI ANALYSIS'}
        </button>
      </div>

      {error && (
        <div style={{ background: '#1a0d0d', border: '1px solid #ff3333', color: '#ff3333', padding: '1rem', fontFamily: 'monospace', fontSize: '0.75rem' }}>
          [!] ERROR: {error}
        </div>
      )}

      {loading && (
        <div style={{ color: '#00ff66', fontFamily: 'monospace', fontSize: '0.75rem', letterSpacing: '0.05em' }}>
          &gt; executing AI reasoning
        </div>
      )}

      {report && !loading && (
        <div style={{ background: '#0a0a0a', border: '1px solid #222', borderLeft: '4px solid #00ff66', padding: '1.25rem', fontFamily: 'monospace', color: '#e0e0e0', fontSize: '0.8rem', lineHeight: '1.6', whiteSpace: 'pre-wrap' }}>
          <div style={{ color: '#00ff66', fontWeight: 'bold', marginBottom: '0.75rem', borderBottom: '1px dashed #222', paddingBottom: '0.4rem', fontSize: '0.7rem' }}>
            AI ANALYSIS
          </div>
          {report}
        </div>
      )}
    </div>
  );
}
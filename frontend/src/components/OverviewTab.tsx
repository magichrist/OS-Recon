import { Repo } from './Repo';
    import { RepoTable } from './RepoTable';

    interface OverviewTabProps {
      scanData?: {
        username?: string;
        metrics?: {
          interesting_count?: number;
          standard_count?: number;
        };
        interesting?: any[];
        standard?: any[];
      } | null;
      showStandardList: boolean;
      setShowStandardList: (show: boolean) => void;
    }

    export function OverviewTab({ scanData, showStandardList, setShowStandardList }: OverviewTabProps) {
      if (!scanData) {
        return (
          <div style={{ border: '1px solid #222', background: '#111', padding: '1rem', fontFamily: 'monospace' }}>
            <p style={{ color: '#666', margin: 0 }}>Waiting for engine payload analysis...</p>
          </div>
        );
      }

      const interestingCount = scanData.metrics?.interesting_count ?? 0;
      const standardCount = scanData.metrics?.standard_count ?? 0;
      const interestingRepos = scanData.interesting || [];
      const standardRepos = scanData.standard || [];

      return (
        <div>
          <div style={{ marginBottom: '2.5rem' }}>
            <h4 style={{ color: '#ff3333', borderBottom: '1px dashed #ff3333', paddingBottom: '0.5rem' }}>
              FLAGGED REPOSITORIES ({interestingCount})
            </h4>
            {interestingRepos.length === 0 ? (
              <p style={{ color: '#888', fontStyle: 'italic' }}>
                No repositories matched sensitive keyword patterns.
              </p>
            ) : (
              interestingRepos.map((repo: any, idx: number) => (
                <Repo key={idx} repo={repo} />
              ))
            )}
          </div>

          <div style={{ marginTop: '2rem' }}>
            <button
              onClick={() => setShowStandardList(!showStandardList)}
              style={{
                background: '#222',
                color: '#fff',
                border: '1px solid #444',
                padding: '0.5rem 1rem',
                cursor: 'pointer',
                fontFamily: 'monospace',
                width: '100%',
                textAlign: 'left',
                display: 'flex',
                justifyContent: 'space-between',
              }}
            >
              <span>
                {showStandardList ? '▼ Hide' : '▶ Show'} all other repositories ({standardCount})
              </span>
              <span>{showStandardList ? 'Collapse' : 'Expand'}</span>
            </button>

            {showStandardList && <RepoTable repos={standardRepos} />}
          </div>
        </div>
      );
    }
```mermaid
flowchart TD
    A[📁 New file created] --> B{YARA Scan}
    
        %% ===== WORKFLOW 1: YARA MATCH =====
            B -->|✅ YARA Match| C[yara.bat<br/>Synchronous Active Response]
                C --> D[Rename + Move → yara_quarantine]
                    D --> E[Wazuh Alert rule 100021]
                        E --> F[Shuffle Webhook<br/>Workflow 1]
                            F --> G[VirusTotal Node<br/>hash lookup enrichment]
                                G --> H[Ollama LLM Node<br/>alert + VT interpretation]
                                    H --> I[📧 SOC Email<br/>Summary / Risk / Quarantine Path / Recommendations]
                                    
                                        %% ===== WORKFLOW 2: FIM / SUSPICIOUS FILE =====
                                            B -->|❌ No YARA Match| J[Wazuh FIM Alert<br/>rules 100001-100008]
                                                J --> K[Shuffle Webhook<br/>Workflow 2]
                                                    K --> L[VirusTotal Node<br/>hash query]
                                                        L --> M{VirusTotal Verdict}
                                                        
                                                            %% --- Subflow 1: Malware Confirmed ---
                                                                M -->|🔴 Malware Confirmed| N[Subflow 1 - Malware Confirmed]
                                                                    N --> O[Malware Quarantine Node<br/>Wazuh Active Response API call]
                                                                        O --> P[📧 Email — Malware Confirmed & Quarantine Action Started]
                                                                        
                                                                            %% --- Subflow 2: Not Confirmed → Correlation ---
                                                                                M -->|🟡 Not Confirmed| Q[Subflow 2<br/>Multistage Attack Correlation]
                                                                                    Q --> R[Related Alerts Query<br/>Wazuh Indexer, time window]
                                                                                        R --> S[Attack Chain Correlation<br/>builds the attack chain]
                                                                                            S --> T[AI Threat Summary<br/>Ollama chain interpretation]
                                                                                                T --> U[📧 Email — Multistage Attack Alert]
                                                                                                
                                                                                                    %% ===== WORKFLOW 3: QUARANTINE STATUS =====
                                                                                                        O -.-> V[Wazuh Active Response Status<br/>rules 100110 / 100111]
                                                                                                            V --> W{Quarantine Succeeded?}
                                                                                                                W -->|✅ Success 100111| X[Logged only<br/>low severity]
                                                                                                                    W -->|❌ Failed 100110| Y[Shuffle Webhook<br/>Workflow 3]
                                                                                                                        Y --> Z[📧 Email — Quarantine Failed<br/>manual action required]
                                                                                                                        
                                                                                                                            classDef workflow1 fill:#1e3a5f,stroke:#4a9eff,color:#fff
                                                                                                                                classDef workflow2 fill:#3a1e5f,stroke:#a44aff,color:#fff
                                                                                                                                    classDef workflow3 fill:#5f1e1e,stroke:#ff4a4a,color:#fff
                                                                                                                                        classDef decision fill:#2f2f2f,stroke:#ffd24a,color:#fff
                                                                                                                                        
                                                                                                                                            class C,D,E,F,G,H,I workflow1
                                                                                                                                                class J,K,L,N,O,P,Q,R,S,T,U workflow2
                                                                                                                                                    class V,W,X,Y,Z workflow3
                                                                                                                                                        class B,M,W decision
                                                                                                                                                        ``````

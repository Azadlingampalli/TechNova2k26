# 🚀 Provenance AI
### AI-Assisted Cyberattack Investigation Platform

Provenance AI is a cybersecurity investigation platform designed to help security analysts understand suspicious activities, trace potential attack paths, and investigate cyber incidents using provenance graphs and anomaly analysis.

## 🌐 Live Demo

- **Live Dashboard:** https://provenanceai.onrender.com
- **API Documentation:** https://technova2k26-1.onrender.com/docs
- **GitHub Repository:** https://github.com/Azadlingampalli/TechNova2k26

## 🎯 Problem Statement

Cybersecurity investigations often involve analyzing large volumes of security events and identifying relationships between suspicious activities.

Traditional investigation workflows can make it difficult to:

- Identify suspicious processes and system activities.
- Understand relationships between security events.
- Trace the sequence of a potential cyberattack.
- Identify relevant attack techniques.
- Present investigation findings clearly.

## 💡 Our Solution

Provenance AI provides a graph-based investigation workflow that organizes security events, analyzes their relationships, identifies potentially suspicious behavior, and helps investigators explore possible attack paths.

The platform combines graph analysis, anomaly scoring, MITRE ATT&CK mapping, and investigation reporting to support cybersecurity analysis.

## ✨ Key Features

### 1. Security Event Analysis

Processes and normalizes security event data to support investigation.

### 2. Provenance Graph Construction

Represents relationships between entities and activities to help investigators understand how events are connected.

### 3. Attack Path Tracing

Helps explore potential sequences of suspicious activities and their relationships.

### 4. Graph Reduction

Simplifies complex graph representations to make relevant entities and relationships easier to investigate.

### 5. Anomaly Scoring

Helps prioritize unusual activities for further investigation.

### 6. MITRE ATT&CK Mapping

Associates relevant findings with MITRE ATT&CK techniques to support standardized analysis of potential attack behavior.

### 7. Investigation Timeline

Helps examine security events in sequence to understand the possible progression of an incident.

### 8. Investigation Reports

Generates summaries of investigation findings for review and further analysis.

### 9. Investigation Data Storage

Uses MongoDB to store and retrieve investigation records when database connectivity is available.

## 🏗️ System Architecture

```text
      Security Event Data
               |
               v
      Event Normalization
               |
               v
    Provenance Graph Building
               |
               v
      Graph Analysis
      and Reduction
               |
               v
     Anomaly Scoring
               |
               v
      Attack Path Tracing
               |
               v
     MITRE ATT&CK Mapping
               |
               v
    Investigation Results
               |
       +-------+-------+
       |               |
       v               v
   Dashboard      Investigation
                  Reports
```

## 🛠️ Technology Stack

| Technology | Purpose |
|---|---|
| Python | Core application logic and analysis |
| Streamlit | Interactive web dashboard |
| FastAPI | Backend API |
| MongoDB | Investigation data storage |
| NetworkX | Graph construction and analysis |
| PyMongo | MongoDB integration |
| Uvicorn | FastAPI application server |
| GitHub | Version control and source-code hosting |
| Render | Cloud deployment |

## 🔄 How It Works

1. **Input:** Security event data is provided to the analysis workflow.
2. **Normalization:** Events are converted into a consistent representation.
3. **Graph Construction:** Relationships between relevant entities and activities are represented as a provenance graph.
4. **Analysis:** Graph analysis and anomaly scoring help identify activities requiring attention.
5. **Attack Tracing:** Potential attack paths are explored through connected events.
6. **Technique Mapping:** Relevant findings are associated with MITRE ATT&CK techniques.
7. **Visualization and Reporting:** Investigation results are presented for review and reporting.

## 📊 Expected Impact

Provenance AI aims to:

- Simplify the investigation of complex security events.
- Improve visibility into relationships between activities.
- Help analysts explore potential attack paths.
- Prioritize suspicious events for further examination.
- Support structured investigation reporting.
- Make graph-based cybersecurity analysis more accessible.

Detection results depend on the quality of the input data and the implemented analysis methods. Findings should be validated before being treated as confirmed malicious activity.

## ⚠️ Limitations

- Evaluation currently uses synthetic and limited-scale datasets. Larger and more diverse real-world datasets can further strengthen evaluation.
- The scoring system uses rule-based heuristics, so suspicious activity may require analyst review before being treated as a confirmed incident.
- Attack-path reconstruction is based on chronological and entity-linked evidence; incomplete event data may affect the reconstructed path.
- MITRE ATT&CK mappings are indicative and can be further validated using additional contextual evidence.
- Graph reduction uses heuristic filtering to simplify complex graphs while retaining relevant investigation evidence.
- The current prototype is optimized for controlled evaluation and demonstration; larger production workloads would require additional performance and security testing.

## 🔮 Future Enhancements

- Real-time security event ingestion.
- Advanced graph-based anomaly detection.
- Interactive provenance graph visualization.
- Expanded MITRE ATT&CK coverage.
- Improved investigation dashboards and reports.
- Additional datasets and evaluation scenarios.
- Enhanced alerting and investigation workflows.

## 👨‍💻 Project Information

- **Project Name:** Provenance AI
- **Category:** Cybersecurity and AI-Assisted Investigation
- **Repository:** [TechNova2k26 on GitHub](https://github.com/Azadlingampalli/TechNova2k26)
- **Dashboard:** [Open Live Dashboard](https://provenanceai.onrender.com)

## 🏁 Conclusion

Provenance AI aims to make cybersecurity investigations more structured and understandable by combining security event analysis, provenance graphs, attack-path tracing, anomaly scoring, and MITRE ATT&CK mapping.

The project provides a foundation for exploring graph-based cyberattack investigation and improving how analysts understand relationships between suspicious activities.

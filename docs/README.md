# Mathematical & Theoretical Formulation

Tài liệu này mô hình hóa toàn bộ kiến trúc hệ thống sang ký hiệu toán học, lý thuyết đồ thị, hàm chấm điểm heuristic và máy trạng thái chuyển tiếp để đưa vào **báo cáo NCKH** và gắn trực tiếp lên **sơ đồ kiến trúc (`architecture-diagram`)**.

---

## 1. Tóm tắt ký hiệu gắn trực tiếp lên Sơ đồ Kiến trúc

Nếu cần vẽ ngắn gọn vào từng khối / mũi tên trên sơ đồ:

| Khối / Giai đoạn trên sơ đồ | Công thức / Ký hiệu ngắn gọn |
|---|---|
| **Static Graph (`graphify`)** | $G = (V, E),\quad p = (v_0 \to v_1 \to \dots \to v_k)$ |
| **Production Filter (`dedup.filter`)** | $G_{\text{prod}} = \{f \in G \mid v_{\text{dst}} \notin V_{\text{non-prod}},\ \text{trim}(p) \neq \emptyset\}$ |
| **Risk Scoring (`dedup.score`)** | $S(f) = 2 + w_{\text{conf}} + w_{\text{sink}}(op) + w_{\text{ctx}} + w_{\text{len}}(\lvert c \rvert)$ |
| **Chunk Ranking (`rank_target_files`)** | $F^* = \arg\max_{F_i} \big(\max_{f \in F_i} S(f),\ \sum_{f \in F_i} S(f)\big)$ |
| **Adversarial Debate ($t \le 3$)** | $(y_t, d_t) \xrightarrow{\delta} \{\text{approved},\ \text{disputed},\ \text{rejected}\}$ |
| **PoV Execution Oracle ($k \le 3$)** | $\text{Exec}(\pi_k) \in \{\text{SUCCESS}, \text{ERROR}_{\tau}\};\quad \text{Verify}(\pi_k, \mathcal{O}) \in \{\text{CONFIRMED}, \text{UNCONFIRMED}, \text{RETRY}\}$ |
| **Disputed Promotion** | $\text{disputed} \xrightarrow{\text{CONFIRMED}} \text{approved} \to \text{Report};\quad \text{disputed} \xrightarrow{\text{UNCONFIRMED}} \text{rejected}$ |

---

## 2. Phase 0: Đồ thị gọi hàm & Lọc mã Production (`graphify` + `src/dedup.py`)

### 2.1. Biểu diễn đồ thị
Mã nguồn mục tiêu được trích xuất thành đồ thị có hướng:
$$G = (V, E)$$
trong đó:
- $V$: tập các hàm / ký hiệu (`nodes`), phân hoạch thành tập production $V_{\text{prod}}$ và tập non-production $V_{\text{non-prod}}$ (`tests/`, `fuzz/`, `mock/`, `fixture/`, `docs/`).
- $E \subseteq V \times V$: tập cạnh gọi hàm (`calls`).
- Một call-flow ứng viên là bộ $f = (v_{\text{src}}, v_{\text{dst}}, P)$, với $P = \{p_1, p_2, \dots\}$ là tập chuỗi đường đi $p = (u_0, u_1, \dots, u_m)$.

### 2.2. Toán tử cắt tiền tố Non-Production (`_clean_prod_paths`)
Với mỗi chuỗi $p = (u_0, \dots, u_m)$, định nghĩa chỉ số bước production đầu tiên:
$$i^* = \min \{ i \in \{0, \dots, m\} \mid u_i \in V_{\text{prod}} \}$$
Đường đi chuẩn hóa là hậu tố $\text{trim}(p) = (u_{i^*}, \dots, u_m)$ (loại bỏ toàn bộ các bước gọi từ unit test ở đầu chuỗi, giữ tối đa $L = 3$ đường đi ngắn nhất không trùng lặp):
$$P_{\text{prod}}(f) = \text{Top}_3^{\text{short}}\Big(\{\text{trim}(p) \mid p \in P,\ \text{trim}(p) \subseteq V_{\text{prod}}\}\Big)$$

---

## 3. Phase 2: Hàm chấm điểm rủi ro & Xếp hạng Chunk (`src/dedup.py`)

### 3.1. Hàm chấm điểm heuristic cho mỗi flow $f$
Từ chuỗi gọi $c = (v_0, \dots, v_k)$, xác định entry point $ep = v_0$, sink operation $op = v_k$, biến nguồn $var$, tệp đích $file$, và độ tin cậy $\text{conf} \in [0, 1]$. Điểm rủi ro $S(f) \in \mathbb{Z}$ được tính đúng theo hàm `score(flow)`:
$$S(f) = 2 + 10 \cdot \mathbb{I}[\text{conf} \ge 0.7 \lor \text{prefix}(id) \in \{\texttt{tf}, \texttt{ct}\} \lor \text{verdict} = \text{VULNERABLE}] + w_{\text{sink}}(op) + w_{\text{ctx}}(f) + w_{\text{len}}(\lvert c \rvert)$$

Trong đó:
- **Trọng số theo nhóm sink nguy hiểm $w_{\text{sink}}(op)$:**
  $$w_{\text{sink}}(op) = w_{\text{primary}}(op) + 7 \cdot \mathbb{I}[op \in \mathcal{O}_{\text{deser}}] + 6 \cdot \mathbb{I}[op \in \mathcal{O}_{\text{file}}] + 5 \cdot \mathbb{I}[op \in \mathcal{O}_{\text{web}}]$$
  với:
  $$w_{\text{primary}}(op) = \begin{cases} 10, & \text{nếu } op \in \mathcal{O}_{\text{RCE}} \\ 8, & \text{nếu } (file \in \text{C/C++} \land op \in \mathcal{O}_{\text{fmt}}) \lor op \in \mathcal{O}_{\text{mem}} \\ 0, & \text{ngược lại} \end{cases}$$

- **Trọng số ngữ cảnh Logic & Auth $w_{\text{ctx}}(f)$:**
  $$w_{\text{ctx}}(f) = 3 \cdot \mathbb{I}[(ep, var) \cap \mathcal{K}_{\text{src}} \neq \emptyset] + 4 \cdot \mathbb{I}[file \cap \mathcal{K}_{\text{auth}} \neq \emptyset] + 4 \cdot \mathbb{I}[(op, ep) \cap \mathcal{K}_{\text{logic}} \neq \emptyset] + 3 \cdot \mathbb{I}[(ep, var, op) \cap \mathcal{K}_{\text{param}} \neq \emptyset] + 4 \cdot \mathbb{I}[file \cap \mathcal{K}_{\text{auth}} \neq \emptyset \land (op, ep) \cap \mathcal{K}_{\text{init}} \neq \emptyset]$$

- **Trọng số độ dài chuỗi $w_{\text{len}}(\lvert c \rvert)$:**
  $$w_{\text{len}}(\lvert c \rvert) = \begin{cases} +2, & 1 \le \lvert c \rvert \le 4 \\ +1, & 5 \le \lvert c \rvert \le 9 \\ -1, & \lvert c \rvert \ge 10 \\ 0, & \lvert c \rvert = 0 \end{cases}$$

### 3.2. Xếp hạng ưu tiên theo File Chunk (`rank_target_files`)
Các flow được gom theo tệp đích $F_i$. Mỗi tệp chưa phân tích được xếp hạng theo bộ khóa từ điển giảm dần (ưu tiên `src/` trước):
$$\text{Priority}(F_i) = \left( \mathbb{I}[F_i \text{ starts with } \texttt{src/}],\ \max_{f \in F_i} S(f),\ \sum_{f \in F_i} S(f) \right)$$

---

## 4. Phase 3: Máy trạng thái Tranh biện Đối kháng (`Coordinator` + `Analyzer` $\leftrightarrow$ `Debator`)

Với mỗi taint flow $f$, quá trình phân tích & phản biện chạy tối đa $T_{\max} = 3$ vòng ($t = 1, 2, 3$):

- **Vuln Analyzer ($\mathcal{A}$):** sinh giả thuyết $H_t = (y_t, E_t^{(A)}, \mathcal{O}_t)$ với $y_t \in \{\text{VULNERABLE}, \text{BENIGN}\}$ và tập bằng chứng code $E_t^{(A)} \neq \emptyset$.
- **Vuln Debator ($\mathcal{D}$):** kiểm chứng độc lập trên đĩa, trả về $D_t = (d_t, E_t^{(D)}, H_t^{(D)})$ với $d_t \in \{\text{ACCEPT}, \text{REJECT}, \text{REVISE}\}$ và $E_t^{(D)} \neq \emptyset$.

Hàm chuyển trạng thái $\delta(y_t, d_t, t)$ kết thúc vào một trong 3 thư mục giả thuyết hoặc sang vòng $t+1$:

$$\delta(y_t, d_t, t) = \begin{cases} \texttt{approved/} & \text{nếu } d_t = \text{ACCEPT} \land y_t = \text{VULNERABLE} \quad (\text{Chủ giả thuyết: } \mathcal{A}) \\ \texttt{rejected/} & \text{nếu } (d_t = \text{ACCEPT} \land y_t = \text{BENIGN}) \lor (t = T_{\max} \land y_t = \text{BENIGN} \land d_t = \text{REVISE}) \\ \texttt{disputed/} & \text{nếu } t = T_{\max} \land y_t = \text{VULNERABLE} \land d_t \in \{\text{REJECT}, \text{REVISE}\} \quad (\text{Chủ giả thuyết: } \mathcal{A}) \\ \texttt{disputed/} & \text{nếu } t = T_{\max} \land y_t = \text{BENIGN} \land d_t = \text{REJECT} \quad (\text{Chủ giả thuyết: } \mathcal{D},\ H_t^{(D)}) \\ \text{Round } (t+1) & \text{nếu } t < T_{\max} \land d_t \in \{\text{REJECT}, \text{REVISE}\} \end{cases}$$

---

## 5. Phase 4: Kiểm chứng Thực nghiệm theo Oracle (`PoV Generator` $\leftrightarrow$ `PoV Verifier`)

Tập ứng viên cần kiểm chứng PoV là hợp của 2 tập:
$$\mathcal{C}_{\text{PoV}} = \mathcal{H}_{\text{approved}} \cup \mathcal{H}_{\text{disputed}}$$

Với mỗi $H \in \mathcal{C}_{\text{PoV}}$ mang oracle kỳ vọng $\mathcal{O}$, vòng tinh chỉnh chạy tối đa $K_{\max} = 3$ lần thử ($k = 1, \dots, K_{\max}$):
1. `PoV Generator` sinh mã khai thác $\pi_k$ và thực thi trong sandbox Linux (ASan/UBSan), trả về trạng thái chạy:
   $$\text{Exec}(\pi_k) = (\text{status}_k, \tau_k),\quad \text{status}_k \in \{\text{SUCCESS}, \text{ERROR}\},\quad \tau_k \in \{\text{timeout}, \text{syntax}, \text{compile}, \text{missing\_dep}, \text{runtime}, \emptyset\}$$
2. `PoV Verifier` kiểm tra tính tái lập và đối khớp hai chiều (vị trí `location_match` & cơ chế `mechanism_match`):
   $$\text{Verify}(\pi_k, \mathcal{O}) = \begin{cases} \text{CONFIRMED}, & \text{nếu } \text{Exec}(\pi_k) \models \mathcal{O} \land \text{Align}(\pi_k, H) \\ \text{RETRY}, & \text{nếu lỗi kịch bản/môi trường } (\text{status}_k = \text{ERROR}) \land k < K_{\max} \\ \text{UNCONFIRMED}, & \text{nếu bất khả thi hoặc } k = K_{\max} \text{ không đạt} \end{cases}$$

**Toán tử hậu kiểm cho tập tranh chấp (`promote_disputed`):**
$$\forall H \in \mathcal{H}_{\text{disputed}}:\quad H \mapsto \begin{cases} \texttt{approved/} \to \texttt{report/vuln\_xxx/}, & \text{nếu } \text{Verify}(\pi, \mathcal{O}) = \text{CONFIRMED} \\ \texttt{rejected/}, & \text{nếu } \text{Verify}(\pi, \mathcal{O}) = \text{UNCONFIRMED} \end{cases}$$

---

## 6. Ràng buộc Dừng & Hội tụ (`BaseAgent`)

Mỗi agent $a$ bị chặn bởi ràng buộc ngân sách bước chạy $S_{\max}$, chi phí $C_{\max}$, và phát hiện lặp lệnh vô hạn:
$$\text{Continue}(a) \iff \big(\text{step}(a) < S_{\max}\big) \land \big(\text{Cost}(a) < C_{\max}\big) \land \big(\text{fail}(cmd) < 3\big) \land \big(\text{dup\_ok}(cmd) < 4\big)$$

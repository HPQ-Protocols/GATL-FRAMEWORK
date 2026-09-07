# Kết quả dành cho bước cập nhật bản thảo

Run: 20260905T073528310255Z_ed073e5d; đã kiểm tra 165375 dòng. Không chạy lại KEM hoặc benchmark.
Latency: 1008 mẫu/method; reliability: 1071 mẫu/method/scenario.

Không dùng thời gian chạy toàn notebook làm latency của protocol.
Bảng LaTeX dùng processing time không gồm KEM/setup/network và application bytes, không phải wire bytes.
Các CI là pointwise, không bảo đảm đồng thời, không kiểm định equivalence. Bootstrap có giả định về tính dừng cục bộ/phụ thuộc yếu.
Raw/auth được chạy khác phase: chênh lệch không phải riêng chi phí HMAC. Memory chỉ là Python-traced peak, không phải RSS.

Đưa measured_results_section.tex cùng thư mục tables/ vào bản thảo để tích hợp sau khi rà soát.
Cần sửa đồng bộ Abstract, Introduction, Discussion và Conclusion; không tự xóa mọi placeholder.
Còn chưa đo: solver/combine/MAC-only, cache ablation, network/MTU/retry/deadline thực, energy và external reproduction.
CHƯA sửa file IEEE-conference-vcris-main.tex trong Prism; gửi cell11_review.zip để cập nhật theo số thật.
Paired gatl_uniform_3_5 - shamir_3_5: 0.207342 ms [-0.175150, 0.621954].
Paired gatl_gateway - rs_2_5_gateway_check: 24.808459 ms [24.382967, 25.261106].

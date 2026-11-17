# README

### `encoding(sound_ref, data_ref, type)`

Nhận vào 1 file .txt hoặc file hình ảnh và dùng LSB để giấu thông tin vào file âm thanh.

**Tham số:**
- `sound_ref` (`str`): Đường dẫn đến file âm thanh cần được giấu tin vào.
- `data_ref` (`str`): Đường dẫn đến file text/hình ảnh cần được nhúng.
- `type` (`str`): Nhập vào 'text' nếu file cần nhúng là .txt, nhập vào 'image' nếu file cần nhúng là hình ảnh.

**Output:**
- Tạo file âm thanh đã được nhúng trong folder `outputs`.


### `decoding(sound_ref, type)`

Nhận vào 1 file âm thanh .wav chứa thông tin đã được nhúng bên trong và trích xuất thông tin đó.

**Tham số:**
- `sound_ref` (`str`): Đường dẫn đến file âm thanh chứa thông tin đã được giấu bên trong.
- `type` (`str`): Nhập vào 'text' nếu thông tin bên trong là text, nhập vào 'image' nếu thông tin bên trong là hình ảnh.

**Output:**
- Tạo file text hoặc hình ảnh đã được trích xuất trong folder `outputs`.
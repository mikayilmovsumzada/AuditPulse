# Fayl Audit Paneli

Linux-da (Kali, Debian, Ubuntu) fayl və qovluqlarla bağlı aşağıdakı hadisələri veb saytda səliqəli göstərir:

- yaradılan, silinən, dəyişdirilən və adı dəyişən fayl və qovluqlar;
- `chmod` (köhnə və yeni icazə) və `chown` (köhnə və yeni sahib) dəyişiklikləri;
- icazəsiz cəhdlər;
- əməliyyatı kimin, hansı proqramla, hansı əmrlə və nə vaxt etdiyi (`sudo` ilə edilənlər də daxil).

Məlumatı Linux-un öz audit sistemindən (`auditd`) götürür. Python 3-dən başqa heç nə tələb etmir.

## Quraşdırma

1. Layihəni yükləyin:
   ```bash
   git clone https://github.com/mikayilmovsumzada/fayl-audit.git && cd fayl-audit
   ```
   (və ya zip faylını açın: `unzip fayl-audit.zip && cd fayl-audit`)
2. Quraşdırın:
   ```bash
   sudo bash install.sh
   ```
3. Brauzerdə açın: **http://127.0.0.1:8088**

Panel kompüter yenidən başlayanda avtomatik işə düşür.

## İzlənən qovluqları dəyişmək

Susmaya görə `/home`, `/etc` və `/root` izlənir. Başqa qovluq əlavə etmək üçün `fileaudit.rules` faylına bu formatda sətir yazın:

```
-w /var/www -p wa -k fa_www
```

Açar (`-k`) mütləq `fa_` ilə başlamalıdır. Sonra `sudo bash install.sh` əmrini yenidən işlədin.

## Saytı şəbəkədən açmaq

Susmaya görə sayt yalnız həmin kompüterdə açılır. Şəbəkədən açmaq üçün `/etc/systemd/system/fileaudit.service` faylında `FA_HOST=127.0.0.1` dəyərini `FA_HOST=0.0.0.0` ilə əvəz edin, sonra bu əmri işlədin:

```bash
sudo systemctl daemon-reload && sudo systemctl restart fileaudit
```

Diqqət: saytda giriş parolu yoxdur, ona görə bunu yalnız etibarlı şəbəkədə edin.

## Silmək

```bash
sudo bash uninstall.sh            # proqramı silir
sudo bash uninstall.sh --hamisi   # məlumat bazasını da silir
```

## Problem olarsa

```bash
systemctl status fileaudit
journalctl -u fileaudit -n 30
sudo auditctl -l        # aktiv audit qaydaları
```

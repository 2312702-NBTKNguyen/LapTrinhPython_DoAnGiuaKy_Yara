import os
import psycopg2
from dotenv import load_dotenv


def ghiLogInfo(thongDiep: str) -> None:
    print(f"[INFO] {thongDiep}")


def ghiLogThanhCong(thongDiep: str) -> None:
    print(f"[SUCCESS] {thongDiep}")


def ghiLogCanhBao(thongDiep: str) -> None:
    print(f"[WARNING] {thongDiep}")


def ghiLogLoi(thongDiep: str) -> None:
    print(f"[ERROR] {thongDiep}")


def layCauHinhKetNoiDb() -> dict[str, str | None]:
    return {
        "host": os.getenv("DB_HOST", "localhost"),
        "port": os.getenv("DB_PORT", "5432"),
        "database": os.getenv("DB_NAME"),
        "user": os.getenv("DB_USER"),
        "password": os.getenv("DB_PASSWORD"),
    }


def taoKetNoiDb() -> psycopg2.extensions.connection:
    cauHinhDb = layCauHinhKetNoiDb()
    host = cauHinhDb.get("host")
    port = cauHinhDb.get("port")
    tenDb = cauHinhDb.get("database")
    user = cauHinhDb.get("user")
    password = cauHinhDb.get("password")

    if not all([host, port, tenDb, user, password]):
        raise ValueError("Thiếu cấu hình kết nối database trong .env hoặc biến môi trường")

    return psycopg2.connect(
        host=host,
        port=port,
        dbname=tenDb,
        user=user,
        password=password,
    )


def canGiuaText(noiDung: str, doRong: int = 100, kyTuDem: str = " ") -> str:
    return noiDung.center(doRong, kyTuDem)


def inMuc(tieuDe: str, doRong: int = 100) -> None:
    thanhNgang = "=" * doRong
    print(f"\n{thanhNgang}")
    print(canGiuaText(tieuDe, doRong=doRong))
    print(thanhNgang)


def khoiTaoMoiTruong(tenDbMacDinh: str = "") -> None:
    load_dotenv()
    os.environ.setdefault("DB_NAME", tenDbMacDinh)

import os

from pathlib import Path
from common.utils import taoKetNoiDb, ghiLogInfo, ghiLogThanhCong, ghiLogCanhBao

def kiemTraSqlFiles() -> None:
    thuMucGoc = Path(__file__).resolve().parent.parent

    danhSachSqlFiles = [
        thuMucGoc / "database" / "01_create_database.sql",
        thuMucGoc / "database" / "02_create_tables.sql",
    ]

    for file in danhSachSqlFiles:
        if not file.exists():
            raise FileNotFoundError(f"Không tìm thấy file SQL: {file}")

def taoDatabaseNeuChuaCo() -> None:
    thuMucGoc = Path(__file__).resolve().parent.parent
    sqlTaoDatabase = thuMucGoc / "database" / "01_create_database.sql"

    with open(sqlTaoDatabase, "r", encoding="utf-8") as fileObj:
        noiDungSqlTaoDb = fileObj.read().strip()

    ghiLogInfo(f"Đọc script: {sqlTaoDatabase}")
    if noiDungSqlTaoDb:
        ghiLogInfo("Thực thi logic tạo database dựa trên nội dung script SQL...")

    ketNoiDb = taoKetNoiDb()
    ketNoiDb.autocommit = True

    try:
        with ketNoiDb.cursor() as conTro:
            sqlCoTheThucThi = noiDungSqlTaoDb.replace("\\gexec", "").strip()
            if not sqlCoTheThucThi:
                raise RuntimeError("Nội dung SQL tạo database rỗng, không thể thực thi")

            conTro.execute(sqlCoTheThucThi)
            dongLenhTao = conTro.fetchone()

            if dongLenhTao and dongLenhTao[0]:
                conTro.execute(dongLenhTao[0])
                ghiLogThanhCong(f"Đã tạo database '{os.getenv('DB_NAME')}' thành công.")
            else:
                ghiLogCanhBao(f"Database '{os.getenv('DB_NAME')}' đã tồn tại. Bỏ qua tạo mới.")
    finally:
        ketNoiDb.close()

def taoTablesNeuChuaCo() -> None:
    thuMucGoc = Path(__file__).resolve().parent.parent
    sqlTaoTables = thuMucGoc / "database" / "02_create_tables.sql"

    with open(sqlTaoTables, "r", encoding="utf-8") as fileObj:
        noiDungSqlTaoTables = fileObj.read().strip()

    ghiLogInfo(f"Đọc script: {sqlTaoTables}")

    ketNoiDb = taoKetNoiDb()
    try:
        with ketNoiDb.cursor() as conTro:
            conTro.execute(noiDungSqlTaoTables)
        ketNoiDb.commit()
        ghiLogThanhCong("Đã cập nhật schema/table thành công.")
    finally:
        ketNoiDb.close()

def thietLapDatabase() -> None:
    kiemTraSqlFiles()
    taoDatabaseNeuChuaCo()
    taoTablesNeuChuaCo()

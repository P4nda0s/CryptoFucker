package com.example.a14473.xp;

import android.content.Context;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;

/**
 * Created by 14473 on 2017/7/3.
 */

public class DBHelper extends SQLiteOpenHelper {

    public DBHelper(Context context, String name, SQLiteDatabase.CursorFactory factory, int version) {
        super(context, name, factory, version);
    }

    @Override
    public void onCreate(SQLiteDatabase sqLiteDatabase) {
        String sql = "CREARE TABLE （" +
                "id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL ," +
                "packageName varchar(256) not null " +
                "Algorithm varchar(64) not null " +
                "datas varchar(4096) not null" ;

    }

    @Override
    public void onUpgrade(SQLiteDatabase sqLiteDatabase, int i, int i1) {

    }
}

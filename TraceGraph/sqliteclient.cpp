/* ===================================================================== */
/* This file is part of TraceGraph                                       */
/* TraceGraph is a tool to visually explore execution traces             */
/* Copyright (C) 2016                                                    */
/* Original author:   Charles Hubain <me@haxelion.eu>                    */
/* Contributors:      Phil Teuwen <phil@teuwen.org>                      */
/*                    Joppe Bos <joppe_bos@hotmail.com>                  */
/*                    Wil Michiels <w.p.a.j.michiels@tue.nl>             */
/*                                                                       */
/* This program is free software: you can redistribute it and/or modify  */
/* it under the terms of the GNU General Public License as published by  */
/* the Free Software Foundation, either version 3 of the License, or     */
/* any later version.                                                    */
/*                                                                       */
/* This program is distributed in the hope that it will be useful,       */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of        */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         */
/* GNU General Public License for more details.                          */
/*                                                                       */
/* You should have received a copy of the GNU General Public License     */
/* along with this program.  If not, see <http://www.gnu.org/licenses/>. */
/* ===================================================================== */
#include "sqliteclient.h"

#include <sstream>
#include <iostream>

SqliteClient::SqliteClient(QObject *parent) :
    QObject(parent)
{
    db = NULL;
}

SqliteClient::~SqliteClient()
{
    cleanup();
}

void SqliteClient::connectToDatabase(QString filename)
{
    if(sqlite3_open_v2(filename.toUtf8().constData(), &db, SQLITE_OPEN_READONLY, NULL) == SQLITE_OK)
    {
        sqlite3_stmt *key_query;

        sqlite3_prepare_v2(db, "SELECT value FROM info where key=?;", -1, &key_query, NULL);

        sqlite3_bind_text(key_query, 1, "TRACERGRIND_VERSION", -1, SQLITE_TRANSIENT);
        if(sqlite3_step(key_query) == SQLITE_ROW) {
            emit connectedToDatabase();
            sqlite3_finalize(key_query);
            return;
        }
        sqlite3_reset(key_query);

        sqlite3_bind_text(key_query, 1, "TRACERPIN_VERSION", -1, SQLITE_TRANSIENT);
        if(sqlite3_step(key_query) == SQLITE_ROW) {
            emit connectedToDatabase();
            sqlite3_finalize(key_query);
            return;
        }
        sqlite3_finalize(key_query);
        cleanup();
        emit invalidDatabase();
    }
    else
    {
        cleanup();
        emit invalidDatabase();
    }
}

void SqliteClient::queryMetadata()
{
    char** metadata = new char*[4];
    sqlite3_stmt *key_query;

    metadata[0] = NULL;
    metadata[1] = NULL;
    metadata[2] = NULL;
    metadata[3] = NULL;

    sqlite3_prepare_v2(db, "SELECT value FROM info where key=?;", -1, &key_query, NULL);

    metadata[0] = NULL;
    sqlite3_bind_text(key_query, 1, "TRACERGRIND_VERSION", -1, SQLITE_TRANSIENT);
    if(sqlite3_step(key_query) == SQLITE_ROW)
    {
        const char *value = (const char*) sqlite3_column_text(key_query, 0);
        if(value != NULL) {
            metadata[0] = new char[strlen(value)+1];
            strcpy(metadata[0], value);
        }
    }
    sqlite3_reset(key_query);

    sqlite3_bind_text(key_query, 1, "TRACERPIN_VERSION", -1, SQLITE_TRANSIENT);
    if(sqlite3_step(key_query) == SQLITE_ROW)
    {
        const char *value = (const char*) sqlite3_column_text(key_query, 0);
        if(value != NULL) {
            metadata[0] = new char[strlen(value)+1];
            strcpy(metadata[0], value);
        }
    }
    sqlite3_reset(key_query);

    sqlite3_bind_text(key_query, 1, "ARCH", -1, SQLITE_TRANSIENT);
    if(sqlite3_step(key_query) == SQLITE_ROW)
    {
        const char *value = (const char*) sqlite3_column_text(key_query, 0);
        if(value != NULL) {
            metadata[1] = new char[strlen(value)+1];
            strcpy(metadata[1], value);
        }
    }
    sqlite3_reset(key_query);

    sqlite3_bind_text(key_query, 1, "PROGRAM", -1, SQLITE_TRANSIENT);
    if(sqlite3_step(key_query) == SQLITE_ROW)
    {
        const char *value = (const char*) sqlite3_column_text(key_query, 0);
        if(value != NULL) {
            metadata[2] = new char[strlen(value)+1];
            strcpy(metadata[2], value);
        }
    }
    sqlite3_reset(key_query);

    sqlite3_bind_text(key_query, 1, "PINPROGRAM", -1, SQLITE_TRANSIENT);
    if(sqlite3_step(key_query) == SQLITE_ROW)
    {
        const char *value = (const char*) sqlite3_column_text(key_query, 0);
        if(value != NULL) {
            metadata[2] = new char[strlen(value)+1];
            strcpy(metadata[2], value);
        }
    }
    sqlite3_reset(key_query);

    sqlite3_bind_text(key_query, 1, "ARGS", -1, SQLITE_TRANSIENT);
    if(sqlite3_step(key_query) == SQLITE_ROW)
    {
        const char *value = (const char*) sqlite3_column_text(key_query, 0);
        if(value != NULL) {
            metadata[3] = new char[strlen(value)+1];
            strcpy(metadata[3], value);
        }
    }
    sqlite3_finalize(key_query);

    emit metadataResults(metadata);
}

void SqliteClient::queryStats()
{
    long long *stats = new long long[3];
    sqlite3_stmt *count_query;
    sqlite3_prepare_v2(db, "SELECT count() FROM bbl;",-1, &count_query, NULL);
    sqlite3_step(count_query);
    stats[0] = sqlite3_column_int64(count_query, 0);
    sqlite3_finalize(count_query);
    sqlite3_prepare_v2(db, "SELECT count() FROM ins;",-1, &count_query, NULL);
    sqlite3_step(count_query);
    stats[1] = sqlite3_column_int64(count_query, 0);
    sqlite3_finalize(count_query);
    sqlite3_prepare_v2(db, "SELECT count() FROM mem;",-1, &count_query, NULL);
    sqlite3_step(count_query);
    stats[2] = sqlite3_column_int64(count_query, 0);
    sqlite3_finalize(count_query);
    emit statResults(stats);
}

void SqliteClient::querySymbols()
{
    sqlite3_stmt *sym_query;
    int num_unk = 0;

    sqlite3_prepare_v2(db, "SELECT path, name, value, size, base, global FROM sym;", -1, &sym_query, NULL);

    while(sqlite3_step(sym_query) == SQLITE_ROW)
    {
        Symbol sym;
        sym.path = (const char*)sqlite3_column_text(sym_query, 0);
        sym.name = (const char*)sqlite3_column_text(sym_query, 1);
        if (sym.name.empty()) {
            std::stringstream value;
            value.str("");
            value.clear();
            value << "unk_" << num_unk;
            sym.name =  value.str();
            ++num_unk;
        }
        sym.value = strtoul((const char *)sqlite3_column_text(sym_query, 2), NULL, 16);
        sym.size = strtoul((const char *)sqlite3_column_text(sym_query, 3), NULL, 16);
        sym.offset = strtoul((const char *)sqlite3_column_text(sym_query, 4), NULL, 16);
        sym.global = strtoul((const char *)sqlite3_column_text(sym_query, 5), NULL, 16) == 1;
        sym.addr = sym.value + sym.offset;
        std::cerr << "name: " << sym.name << " addr: " << sym.addr << " value: " << sym.value << " size: " << sym.size << " offset: " << sym.offset << " global: " << sym.global << "\n";
        if (sym.global) {
            syms.insert(std::make_pair(sym.addr, sym));
        }
    }

    std::cerr << "syms size: " << syms.size() << "\n";
    sqlite3_finalize(sym_query);
    emit symResults(syms);
}

void SqliteClient::queryEvents()
{
    unsigned long long time = 0;
    sqlite3_stmt *ins_query, *mem_query;


    sqlite3_prepare_v2(db, "SELECT rowid, ip, op FROM ins;", -1, &ins_query, NULL);
    sqlite3_prepare_v2(db, "SELECT rowid, ins_id, type, addr, size FROM mem;", -1, &mem_query, NULL);
    sqlite3_step(mem_query);

    while(sqlite3_step(ins_query) == SQLITE_ROW)
    {
        Event ins_ev;
        ins_ev.type = EVENT_INS;
        ins_ev.id = sqlite3_column_int64(ins_query, 0);
        ins_ev.address = strtoul((const char*) sqlite3_column_text(ins_query, 1), NULL, 16);
        ins_ev.size = strlen((const char*) sqlite3_column_text(ins_query, 2))/2;
        ins_ev.time = time;

        sqlite3_bind_int64(mem_query, 1, ins_ev.id);

        while(sqlite3_column_int(mem_query, 1) == ins_ev.id)
        {
            Event mem_ev;
            mem_ev.id = sqlite3_column_int64(mem_query, 0);
            if(strcmp((const char*) sqlite3_column_text(mem_query, 2), "R") == 0)
                mem_ev.type = EVENT_R;
            else if(strcmp((const char*) sqlite3_column_text(mem_query, 2), "W") == 0)
                mem_ev.type = EVENT_W;
            else
                mem_ev.type = EVENT_UFO;
            mem_ev.address = strtoul((const char*) sqlite3_column_text(mem_query, 3), NULL, 16);
            mem_ev.size = sqlite3_column_int(mem_query, 4);
            mem_ev.time = time;

            emit receivedEvent(mem_ev);
            sqlite3_step(mem_query);
        }

        emit receivedEvent(ins_ev);
        time++;
    }

    sqlite3_finalize(ins_query);
    sqlite3_finalize(mem_query);
    emit dbProcessingFinished();
}

void SqliteClient::queryEventDescription(Event ev)
{
    QString description;
    sqlite3_stmt *query;
    if(ev.type == EVENT_INS)
        sqlite3_prepare_v2(db, "SELECT * from INS where rowid=?;", -1, &query, NULL);
    else if(ev.type == EVENT_R || ev.type == EVENT_W)
        sqlite3_prepare_v2(db, "SELECT * from mem where rowid=?;", -1, &query, NULL);
    else
    {
        description = "Unkown event type.";
        emit receivedEventDescription(description);
        return;
    }

    sqlite3_bind_int64(query, 1, ev.id);
    if(sqlite3_step(query) == SQLITE_ROW)
    {
        int i;
        int column_count = sqlite3_column_count(query);
        for(i = 0; i < column_count; i++)
        {
            std::string name(sqlite3_column_name(query, i));
            description.append(name.c_str());
            description.append(": ");
            description.append((const char*)sqlite3_column_text(query, i));
            description.append("\n");
            if (name == "ip" || name == "addr" || name == "addr_end") {
                uint64_t addr = strtoul((const char*)sqlite3_column_text(query, i), NULL, 16);
                auto sym = ::findSym(syms, addr);
                description.append(name.c_str());
                description.append(": ");
                if (sym) {
                    char buffer[256];
                    snprintf(buffer, sizeof(buffer), "%s + 0x%lx", sym->name.c_str(), addr - sym->addr);
                    description.append(buffer);
                } else {
                    description.append("unknown");
                }
                description.append("\n");
            }
        }
    }
    else
    {
        description = "Event not found in database.";
    }

    emit receivedEventDescription(description);
}

void SqliteClient::cleanup()
{
    if(db)
    {
        sqlite3_close(db);
        db = NULL;
    }
}

const Symbol* findSym(Symbols &syms, uint64_t addr) {
    const auto it = syms.find(addr);
    if (it != syms.end()) {
        return &it->second;
    } else {
        const auto it2 = syms.lower_bound(addr);
        return &std::prev(it2)->second;
    }
}

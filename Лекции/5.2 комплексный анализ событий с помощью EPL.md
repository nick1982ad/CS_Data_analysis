# Примеры данных для Esper Notebook / EPL Online

> Каждый пример содержит **EPL-блок** (`%esperepl`) и **Сценарий** (`%esperscenario`).
> Формат совместим с EPL Online (esper-epl-tryout.appspot.com).
---

## Пример 1 — Фильтрация событий: мониторинг температуры

**Задача:** отслеживать показания датчиков и выявлять критические значения.

### EPL

```
%esperepl

create schema SensorReading(sensorId string, location string, tempC double, humidity double);

@name('HighTemp')
select sensorId, location, tempC
from SensorReading(tempC > 80);

@name('AvgTemp')
select location, avg(tempC) as avgTemp, count(*) as cnt
from SensorReading#time(30 sec)
group by location;
```

### Сценарий

```
%esperscenario

t = '2025-06-15 10:00:00.000'
SensorReading = {sensorId='S01', location='ServerRoom-A', tempC=22.5, humidity=45.0}
SensorReading = {sensorId='S02', location='ServerRoom-B', tempC=24.1, humidity=50.2}

t = t + 5000
SensorReading = {sensorId='S01', location='ServerRoom-A', tempC=35.0, humidity=42.0}
SensorReading = {sensorId='S03', location='ServerRoom-A', tempC=78.0, humidity=30.0}

t = t + 5000
SensorReading = {sensorId='S01', location='ServerRoom-A', tempC=85.3, humidity=28.0}
SensorReading = {sensorId='S02', location='ServerRoom-B', tempC=26.0, humidity=48.0}

t = t + 5000
SensorReading = {sensorId='S03', location='ServerRoom-A', tempC=92.1, humidity=22.0}
SensorReading = {sensorId='S01', location='ServerRoom-A', tempC=88.7, humidity=25.0}

t = t + 10000
SensorReading = {sensorId='S01', location='ServerRoom-A', tempC=45.0, humidity=40.0}
SensorReading = {sensorId='S02', location='ServerRoom-B', tempC=23.5, humidity=51.0}
```

**Что демонстрирует:**
- Фильтрация в FROM-clause: `SensorReading(tempC > 80)` — только горячие
- Временное окно `#time(30 sec)` — скользящее окно 30 секунд
- Агрегация `avg()`, `count()` с `group by`

---

## Пример 2 — Скользящие окна: анализ биржевых котировок

**Задача:** непрерывное отслеживание средней цены и выявление резких скачков.

### EPL

```
%esperepl

create schema StockTick(symbol string, price double, volume long);

@name('AvgPrice30s')
select symbol, avg(price) as avgPrice, min(price) as minPrice, max(price) as maxPrice, count(*) as tickCount
from StockTick#time(30 sec)
group by symbol;

@name('PriceSpike')
select a.symbol, a.price as currentPrice, b.price as prevPrice,
       (a.price - b.price) / b.price * 100 as changePercent
from pattern [every b=StockTick -> a=StockTick(symbol=b.symbol)]
where (a.price - b.price) / b.price > 0.05 or (b.price - a.price) / b.price > 0.05;
```

### Сценарий

```
%esperscenario

t = '2025-06-15 09:30:00.000'
StockTick = {symbol='AAPL', price=185.50, volume=1200}
StockTick = {symbol='GOOG', price=140.20, volume=800}

t = t + 2000
StockTick = {symbol='AAPL', price=186.00, volume=1500}
StockTick = {symbol='GOOG', price=141.00, volume=900}

t = t + 2000
StockTick = {symbol='AAPL', price=186.30, volume=1100}
StockTick = {symbol='GOOG', price=139.80, volume=700}

t = t + 3000
StockTick = {symbol='AAPL', price=196.00, volume=5000}

t = t + 2000
StockTick = {symbol='GOOG', price=148.50, volume=4200}

t = t + 2000
StockTick = {symbol='AAPL', price=197.10, volume=3800}
StockTick = {symbol='GOOG', price=147.90, volume=2100}

t = t + 5000
StockTick = {symbol='AAPL', price=192.00, volume=2500}
StockTick = {symbol='GOOG', price=142.00, volume=1600}

t = t + 20000
StockTick = {symbol='AAPL', price=190.50, volume=1000}
```

**Что демонстрирует:**
- Скользящее окно `#time(30 sec)` с агрегацией по группам
- Паттерн `every b -> a` — отслеживание последовательных тиков одного инструмента
- Вычисляемое выражение — процент изменения цены (> 5%)

---

## Пример 3 — Паттерны: обнаружение сетевых аномалий (IDS)

**Задача:** обнаружение brute-force атак — 5+ неудачных попыток входа за 60 секунд с одного IP.

### EPL

```
%esperepl

create schema LoginAttempt(srcIp string, dstIp string, username string, success boolean, port int);

@name('FailedLogins')
select srcIp, dstIp, count(*) as failCount
from LoginAttempt(success=false)#time(60 sec)
group by srcIp, dstIp
having count(*) >= 5;

@name('BruteForcePattern')
select a.srcIp, a.dstIp, a.username
from pattern [every a=LoginAttempt(success=false)
  -> (timer:interval(2 sec) and not LoginAttempt(srcIp=a.srcIp, success=true))];

@name('SuccessAfterFail')
select fail.srcIp, fail.username as failUser, ok.username as successUser
from pattern [every fail=LoginAttempt(success=false)
  -> ok=LoginAttempt(srcIp=fail.srcIp, success=true, dstIp=fail.dstIp)];
```

### Сценарий

```
%esperscenario

t = '2025-06-15 14:00:00.000'
LoginAttempt = {srcIp='10.0.1.50', dstIp='192.168.1.10', username='admin', success=false, port=22}

t = t + 1000
LoginAttempt = {srcIp='10.0.1.50', dstIp='192.168.1.10', username='admin', success=false, port=22}

t = t + 1000
LoginAttempt = {srcIp='10.0.1.50', dstIp='192.168.1.10', username='root', success=false, port=22}

t = t + 1500
LoginAttempt = {srcIp='10.0.1.50', dstIp='192.168.1.10', username='admin', success=false, port=22}

t = t + 1000
LoginAttempt = {srcIp='10.0.1.50', dstIp='192.168.1.10', username='user1', success=false, port=22}

t = t + 800
LoginAttempt = {srcIp='10.0.1.50', dstIp='192.168.1.10', username='admin', success=false, port=22}

t = t + 2000
LoginAttempt = {srcIp='10.0.1.50', dstIp='192.168.1.10', username='admin', success=true, port=22}

t = t + 5000
LoginAttempt = {srcIp='172.16.0.5', dstIp='192.168.1.20', username='operator', success=false, port=3389}

t = t + 3000
LoginAttempt = {srcIp='172.16.0.5', dstIp='192.168.1.20', username='operator', success=true, port=3389}
```

**Что демонстрирует:**
- Фильтрация `LoginAttempt(success=false)` в FROM
- HAVING для порога срабатывания (≥ 5 неудач)
- Паттерн `-> (timer:interval and not ...)` — отсутствие успешного входа
- Паттерн `fail -> ok` — успешный вход после серии неудач

---

## Пример 4 — Batch-окна и OUTPUT: агрегация по интервалам

**Задача:** считать количество HTTP-запросов по статусам каждые 10 секунд.

### EPL

```
%esperepl

create schema HttpRequest(method string, url string, statusCode int, responseTimeMs long, clientIp string);

@name('RequestsPerBatch')
select count(*) as totalRequests,
       sum(case when statusCode >= 200 and statusCode < 300 then 1 else 0 end) as success2xx,
       sum(case when statusCode >= 400 and statusCode < 500 then 1 else 0 end) as client4xx,
       sum(case when statusCode >= 500 then 1 else 0 end) as server5xx,
       avg(responseTimeMs) as avgResponseMs
from HttpRequest#time_batch(10 sec);

@name('SlowRequests')
select method, url, statusCode, responseTimeMs
from HttpRequest(responseTimeMs > 500);
```

### Сценарий

```
%esperscenario

t = '2025-06-15 12:00:00.000'
HttpRequest = {method='GET', url='/api/users', statusCode=200, responseTimeMs=45, clientIp='10.0.0.1'}
HttpRequest = {method='POST', url='/api/orders', statusCode=201, responseTimeMs=120, clientIp='10.0.0.2'}
HttpRequest = {method='GET', url='/api/products', statusCode=200, responseTimeMs=30, clientIp='10.0.0.3'}

t = t + 2000
HttpRequest = {method='GET', url='/api/users/999', statusCode=404, responseTimeMs=15, clientIp='10.0.0.1'}
HttpRequest = {method='POST', url='/api/auth', statusCode=401, responseTimeMs=22, clientIp='10.0.0.5'}

t = t + 3000
HttpRequest = {method='GET', url='/api/reports', statusCode=200, responseTimeMs=850, clientIp='10.0.0.2'}
HttpRequest = {method='GET', url='/api/dashboard', statusCode=500, responseTimeMs=1200, clientIp='10.0.0.4'}
HttpRequest = {method='POST', url='/api/upload', statusCode=503, responseTimeMs=5000, clientIp='10.0.0.6'}

t = t + 5000
HttpRequest = {method='GET', url='/api/health', statusCode=200, responseTimeMs=5, clientIp='10.0.0.1'}
HttpRequest = {method='DELETE', url='/api/cache', statusCode=204, responseTimeMs=10, clientIp='10.0.0.3'}

t = t + 5000
HttpRequest = {method='GET', url='/api/users', statusCode=200, responseTimeMs=42, clientIp='10.0.0.1'}
HttpRequest = {method='POST', url='/api/orders', statusCode=201, responseTimeMs=95, clientIp='10.0.0.2'}
HttpRequest = {method='GET', url='/api/slow-query', statusCode=200, responseTimeMs=3200, clientIp='10.0.0.7'}

t = t + 5000
HttpRequest = {method='GET', url='/api/products', statusCode=200, responseTimeMs=28, clientIp='10.0.0.3'}
```

**Что демонстрирует:**
- Пакетное окно `#time_batch(10 sec)` — выдаёт результат каждые 10 сек
- `CASE WHEN` внутри агрегации — подсчёт по категориям
- Фильтрация медленных запросов `responseTimeMs > 500`

---

## Пример 5 — Named Windows и ON MERGE: таблица состояния оборудования

**Задача:** поддерживать актуальную таблицу состояния устройств и отслеживать переходы в статус ALARM.

### EPL

```
%esperepl

create schema DeviceStatus(deviceId string, status string, value double, timestamp long);

create window DeviceState#unique(deviceId) as (deviceId string, status string, value double, lastSeen long);

@name('MergeState')
on DeviceStatus as ds
merge DeviceState as state
where state.deviceId = ds.deviceId
when matched then
  update set status = ds.status, value = ds.value, lastSeen = ds.timestamp
when not matched then
  insert select ds.deviceId, ds.status, ds.value, ds.timestamp as lastSeen;

@name('AlarmDetection')
select ds.deviceId, ds.status, ds.value
from DeviceStatus(status='ALARM') as ds;

@name('CurrentState')
select deviceId, status, value, lastSeen
from DeviceState;
```

### Сценарий

```
%esperscenario

t = '2025-06-15 08:00:00.000'
DeviceStatus = {deviceId='PLC-001', status='OK', value=72.0, timestamp=1718438400000}
DeviceStatus = {deviceId='PLC-002', status='OK', value=68.5, timestamp=1718438400000}
DeviceStatus = {deviceId='RTU-010', status='OK', value=55.0, timestamp=1718438400000}

t = t + 10000
DeviceStatus = {deviceId='PLC-001', status='OK', value=73.2, timestamp=1718438410000}
DeviceStatus = {deviceId='PLC-002', status='WARNING', value=82.0, timestamp=1718438410000}

t = t + 10000
DeviceStatus = {deviceId='PLC-002', status='ALARM', value=95.3, timestamp=1718438420000}
DeviceStatus = {deviceId='RTU-010', status='OK', value=54.8, timestamp=1718438420000}

t = t + 10000
DeviceStatus = {deviceId='PLC-001', status='ALARM', value=98.1, timestamp=1718438430000}
DeviceStatus = {deviceId='PLC-002', status='ALARM', value=97.0, timestamp=1718438430000}

t = t + 10000
DeviceStatus = {deviceId='PLC-002', status='OK', value=70.0, timestamp=1718438440000}
DeviceStatus = {deviceId='RTU-010', status='WARNING', value=80.5, timestamp=1718438440000}
```

**Что демонстрирует:**
- Named Window с `#unique(deviceId)` — одна запись на устройство
- `ON MERGE ... WHEN MATCHED / WHEN NOT MATCHED` — upsert-логика
- Отдельный statement для алармов с фильтрацией `status='ALARM'`

---

## Пример 6 — Context Partitions: сегментация по ключу

**Задача:** отдельная агрегация по каждому сетевому интерфейсу с выдачей каждые 10 секунд.

### EPL

```
%esperepl

create schema NetFlowEvent(interfaceId string, bytesIn long, bytesOut long, packets long);

create context PerInterface partition by interfaceId from NetFlowEvent;

@name('TrafficPerInterface')
context PerInterface
select context.key1 as interfaceId,
       sum(bytesIn) as totalBytesIn,
       sum(bytesOut) as totalBytesOut,
       sum(packets) as totalPackets,
       count(*) as eventCount
from NetFlowEvent#time_batch(10 sec);
```

### Сценарий

```
%esperscenario

t = '2025-06-15 15:00:00.000'
NetFlowEvent = {interfaceId='eth0', bytesIn=15000, bytesOut=8000, packets=120}
NetFlowEvent = {interfaceId='eth1', bytesIn=5000, bytesOut=3000, packets=45}
NetFlowEvent = {interfaceId='eth0', bytesIn=22000, bytesOut=11000, packets=180}

t = t + 3000
NetFlowEvent = {interfaceId='eth0', bytesIn=18000, bytesOut=9500, packets=150}
NetFlowEvent = {interfaceId='eth1', bytesIn=7500, bytesOut=4200, packets=60}
NetFlowEvent = {interfaceId='wlan0', bytesIn=3000, bytesOut=1500, packets=25}

t = t + 3000
NetFlowEvent = {interfaceId='eth0', bytesIn=25000, bytesOut=12000, packets=200}
NetFlowEvent = {interfaceId='wlan0', bytesIn=4500, bytesOut=2000, packets=35}

t = t + 4000
NetFlowEvent = {interfaceId='eth1', bytesIn=6000, bytesOut=3500, packets=50}
NetFlowEvent = {interfaceId='eth0', bytesIn=20000, bytesOut=10000, packets=160}

t = t + 5000
NetFlowEvent = {interfaceId='eth0', bytesIn=17000, bytesOut=8500, packets=140}
NetFlowEvent = {interfaceId='eth1', bytesIn=8000, bytesOut=4500, packets=65}
NetFlowEvent = {interfaceId='wlan0', bytesIn=2000, bytesOut=1000, packets=20}
```

**Что демонстрирует:**
- `create context ... partition by` — отдельный контекст на каждый interfaceId
- `context.key1` — доступ к ключу партиции
- Комбинация контекста с `#time_batch(10 sec)`

---

## Пример 7 — JOIN потоков: корреляция событий из разных источников

**Задача:** сопоставить события аутентификации VPN с событиями доступа к файловой системе для аудита.

### EPL

```
%esperepl

create schema VpnConnect(userId string, srcIp string, vpnIp string, connectTime long);
create schema FileAccess(userId string, filePath string, action string, accessTime long);

@name('VpnFileCorrelation')
select vpn.userId, vpn.srcIp, vpn.vpnIp, fa.filePath, fa.action
from VpnConnect#time(60 sec) as vpn
inner join FileAccess#time(60 sec) as fa
on vpn.userId = fa.userId;

@name('SensitiveAccess')
select vpn.userId, vpn.srcIp, fa.filePath, fa.action
from VpnConnect#time(60 sec) as vpn
inner join FileAccess(action='DELETE' or action='DOWNLOAD')#time(60 sec) as fa
on vpn.userId = fa.userId;
```

### Сценарий

```
%esperscenario

t = '2025-06-15 09:00:00.000'
VpnConnect = {userId='ivanov', srcIp='203.0.113.10', vpnIp='10.8.0.5', connectTime=1718434800000}

t = t + 2000
VpnConnect = {userId='petrov', srcIp='198.51.100.20', vpnIp='10.8.0.6', connectTime=1718434802000}

t = t + 3000
FileAccess = {userId='ivanov', filePath='/data/reports/q1.xlsx', action='READ', accessTime=1718434805000}

t = t + 2000
FileAccess = {userId='ivanov', filePath='/data/configs/firewall.conf', action='DOWNLOAD', accessTime=1718434807000}

t = t + 1000
FileAccess = {userId='petrov', filePath='/data/hr/salaries.csv', action='READ', accessTime=1718434808000}

t = t + 3000
FileAccess = {userId='petrov', filePath='/data/hr/salaries.csv', action='DELETE', accessTime=1718434811000}

t = t + 5000
FileAccess = {userId='ivanov', filePath='/data/logs/audit.log', action='READ', accessTime=1718434816000}

t = t + 5000
VpnConnect = {userId='sidorov', srcIp='192.0.2.30', vpnIp='10.8.0.7', connectTime=1718434821000}
FileAccess = {userId='sidorov', filePath='/data/backup/db_dump.sql', action='DOWNLOAD', accessTime=1718434821000}
```

**Что демонстрирует:**
- `INNER JOIN` двух потоков с временными окнами
- Корреляция по `userId` между VPN и файловым доступом
- Дополнительная фильтрация в JOIN: `action='DELETE' or action='DOWNLOAD'`

---

## Пример 8 — INSERT INTO + каскадная обработка: конвейер событий

**Задача:** из потока сырых метрик вычислить средние, затем обнаружить аномалии.

### EPL

```
%esperepl

create schema RawMetric(host string, cpu double, memUsed double, diskIO long);

@name('Stage1_Avg')
insert into HostAvgMetric
select host, avg(cpu) as avgCpu, avg(memUsed) as avgMem, sum(diskIO) as totalIO
from RawMetric#time_batch(10 sec)
group by host;

@name('Stage2_Anomaly')
select host, avgCpu, avgMem, totalIO,
       case
         when avgCpu > 90 and avgMem > 85 then 'CRITICAL'
         when avgCpu > 80 or avgMem > 80 then 'WARNING'
         else 'OK'
       end as severity
from HostAvgMetric
where avgCpu > 80 or avgMem > 80;
```

### Сценарий

```
%esperscenario

t = '2025-06-15 11:00:00.000'
RawMetric = {host='web-01', cpu=45.0, memUsed=60.0, diskIO=1200}
RawMetric = {host='web-02', cpu=30.0, memUsed=55.0, diskIO=800}
RawMetric = {host='db-01', cpu=70.0, memUsed=78.0, diskIO=5000}

t = t + 3000
RawMetric = {host='web-01', cpu=52.0, memUsed=62.0, diskIO=1400}
RawMetric = {host='db-01', cpu=85.0, memUsed=82.0, diskIO=7500}

t = t + 3000
RawMetric = {host='web-01', cpu=88.0, memUsed=75.0, diskIO=2000}
RawMetric = {host='web-02', cpu=35.0, memUsed=58.0, diskIO=900}
RawMetric = {host='db-01', cpu=92.0, memUsed=88.0, diskIO=9000}

t = t + 4000
RawMetric = {host='web-01', cpu=91.0, memUsed=80.0, diskIO=2200}
RawMetric = {host='db-01', cpu=95.0, memUsed=92.0, diskIO=12000}

t = t + 5000
RawMetric = {host='web-01', cpu=50.0, memUsed=60.0, diskIO=1100}
RawMetric = {host='web-02', cpu=32.0, memUsed=54.0, diskIO=750}
RawMetric = {host='db-01', cpu=60.0, memUsed=65.0, diskIO=4000}

t = t + 10000
RawMetric = {host='web-01', cpu=40.0, memUsed=58.0, diskIO=1000}
```

**Что демонстрирует:**
- `INSERT INTO` — создание нового потока `HostAvgMetric` из агрегированных данных
- Каскад: Stage1 агрегирует → Stage2 анализирует
- `CASE WHEN` для классификации severity

---

## Пример 9 — Таймеры и отсутствие событий: heartbeat-мониторинг

**Задача:** если устройство не присылает heartbeat в течение 15 секунд — сгенерировать алерт.

### EPL

```
%esperepl

create schema Heartbeat(deviceId string, seqNum int);
create schema DeviceOfflineAlert(deviceId string, lastSeqNum int);

@name('MissedHeartbeat')
insert into DeviceOfflineAlert
select hb.deviceId, hb.seqNum as lastSeqNum
from pattern [every hb=Heartbeat -> (timer:interval(15 sec) and not Heartbeat(deviceId=hb.deviceId))];

@name('ShowAlerts')
select * from DeviceOfflineAlert;
```

### Сценарий

```
%esperscenario

t = '2025-06-15 16:00:00.000'
Heartbeat = {deviceId='GW-001', seqNum=1}
Heartbeat = {deviceId='GW-002', seqNum=1}
Heartbeat = {deviceId='GW-003', seqNum=1}

t = t + 5000
Heartbeat = {deviceId='GW-001', seqNum=2}
Heartbeat = {deviceId='GW-002', seqNum=2}
Heartbeat = {deviceId='GW-003', seqNum=2}

t = t + 5000
Heartbeat = {deviceId='GW-001', seqNum=3}
Heartbeat = {deviceId='GW-002', seqNum=3}

t = t + 5000
Heartbeat = {deviceId='GW-001', seqNum=4}
Heartbeat = {deviceId='GW-002', seqNum=4}

t = t + 5000
Heartbeat = {deviceId='GW-001', seqNum=5}

t = t + 5000
Heartbeat = {deviceId='GW-001', seqNum=6}

t = t + 10000
Heartbeat = {deviceId='GW-001', seqNum=7}
Heartbeat = {deviceId='GW-002', seqNum=5}
Heartbeat = {deviceId='GW-003', seqNum=3}
```

**Что демонстрирует:**
- Паттерн `every hb -> (timer:interval(15 sec) and not ...)` — обнаружение отсутствия
- GW-003 замолкает после seqNum=2, алерт через 15 сек
- GW-002 замолкает позже, тоже получает алерт
- `INSERT INTO DeviceOfflineAlert` — результат как новый поток

---

## Пример 10 — IEC 61850: мониторинг GOOSE-сообщений подстанции

**Задача:** обнаружение аномалий в GOOSE-трафике цифровой подстанции — дубликаты stNum, пропуски sqNum, подозрительно частые retransmission.

### EPL

```
%esperepl

create schema GooseMessage(
  srcMac string,
  goCbRef string,
  stNum int,
  sqNum int,
  confRev int,
  allData string,
  captureTimeMs long
);

// Обнаружение дублей stNum (replay-атака или сбой)
@name('DuplicateStNum')
select a.goCbRef, a.stNum, a.srcMac, a.sqNum as sqA, b.sqNum as sqB
from pattern [every a=GooseMessage
  -> b=GooseMessage(goCbRef=a.goCbRef, stNum=a.stNum, sqNum<a.sqNum)
  where timer:within(5 sec)];

// stNum увеличился более чем на 1 — возможный пропуск
@name('StNumGap')
select a.goCbRef, a.stNum as prevStNum, b.stNum as newStNum, (b.stNum - a.stNum) as gap
from pattern [every a=GooseMessage
  -> b=GooseMessage(goCbRef=a.goCbRef, stNum > a.stNum + 1)
  where timer:within(10 sec)];

// Высокая частота: более 10 GOOSE за 1 секунду от одного источника
@name('HighFrequency')
select goCbRef, srcMac, count(*) as msgCount
from GooseMessage#time(1 sec)
group by goCbRef, srcMac
having count(*) > 10;

// Изменение confRev — возможная подмена конфигурации
@name('ConfRevChange')
select a.goCbRef, a.confRev as oldRev, b.confRev as newRev, b.srcMac
from pattern [every a=GooseMessage
  -> b=GooseMessage(goCbRef=a.goCbRef, confRev != a.confRev)
  where timer:within(30 sec)];
```

### Сценарий

```
%esperscenario

t = '2025-06-15 20:00:00.000'
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=100, sqNum=0, confRev=1, allData='pos:ON', captureTimeMs=1718488800000}

t = t + 100
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=100, sqNum=1, confRev=1, allData='pos:ON', captureTimeMs=1718488800100}

t = t + 100
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=100, sqNum=2, confRev=1, allData='pos:ON', captureTimeMs=1718488800200}

// Нормальное изменение состояния
t = t + 500
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=101, sqNum=0, confRev=1, allData='pos:OFF', captureTimeMs=1718488800700}

t = t + 100
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=101, sqNum=1, confRev=1, allData='pos:OFF', captureTimeMs=1718488800800}

// АНОМАЛИЯ: дубль stNum с меньшим sqNum — возможный replay
t = t + 200
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=101, sqNum=0, confRev=1, allData='pos:ON', captureTimeMs=1718488801000}

// АНОМАЛИЯ: пропуск stNum (101 -> 105)
t = t + 2000
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=105, sqNum=0, confRev=1, allData='pos:ON', captureTimeMs=1718488803000}

t = t + 100
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=105, sqNum=1, confRev=1, allData='pos:ON', captureTimeMs=1718488803100}

// АНОМАЛИЯ: изменение confRev — подмена конфигурации?
t = t + 3000
GooseMessage = {srcMac='00:0A:0B:0C:0D:0E', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=106, sqNum=0, confRev=2, allData='pos:OFF', captureTimeMs=1718488806000}

// АНОМАЛИЯ: burst — 12 сообщений за 1 секунду
t = t + 2000
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=107, sqNum=0, confRev=1, allData='pos:ON', captureTimeMs=1718488808000}
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=107, sqNum=1, confRev=1, allData='pos:ON', captureTimeMs=1718488808050}
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=107, sqNum=2, confRev=1, allData='pos:ON', captureTimeMs=1718488808100}
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=107, sqNum=3, confRev=1, allData='pos:ON', captureTimeMs=1718488808150}
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=107, sqNum=4, confRev=1, allData='pos:ON', captureTimeMs=1718488808200}
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=107, sqNum=5, confRev=1, allData='pos:ON', captureTimeMs=1718488808250}
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=107, sqNum=6, confRev=1, allData='pos:ON', captureTimeMs=1718488808300}
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=107, sqNum=7, confRev=1, allData='pos:ON', captureTimeMs=1718488808350}
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=107, sqNum=8, confRev=1, allData='pos:ON', captureTimeMs=1718488808400}
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=107, sqNum=9, confRev=1, allData='pos:ON', captureTimeMs=1718488808450}
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=107, sqNum=10, confRev=1, allData='pos:ON', captureTimeMs=1718488808500}
GooseMessage = {srcMac='00:01:02:03:04:05', goCbRef='AA1J1Q01A1/LLN0$GO$gcb01', stNum=107, sqNum=11, confRev=1, allData='pos:ON', captureTimeMs=1718488808550}
```

**Что демонстрирует:**
- Полноценный IEC 61850 GOOSE-мониторинг через EPL
- Replay-атака: дубль stNum с откатом sqNum
- Пропуск stNum: 101 → 105 (gap = 4)
- Подмена confRev с другого MAC-адреса
- Burst-аномалия: > 10 сообщений за 1 сек
- Комбинация паттернов, фильтров, HAVING и временных окон

---

## Справка: синтаксис сценариев

| Инструкция | Описание |
|---|---|
| `t = '2025-01-01T10:00:00.000'` | Установить абсолютное время |
| `t = t + 5000` | Продвинуть время на 5 секунд (мс) |
| `MyEvent = {prop1='val', prop2=42}` | Отправить событие |
| `MyEvent = {nested={a=1, b=2}}` | Вложенное событие |
| `MyEvent = {arr={'x', 'y', 'z'}}` | Массив значений |

> **Esper Notebook:** разделяйте EPL и сценарии на разные параграфы (`%esperepl` и `%esperscenario`).
> **EPL Online:** EPL в левую панель, события с временем — в среднюю.

using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

#if DEBUG
using System.Diagnostics;
// ReSharper disable UnusedAutoPropertyAccessor.Global
// ReSharper disable UnusedMember.Global
// ReSharper disable MemberCanBePrivate.Global
#endif

namespace Leaf.xNet
{
    /// <summary>
    /// Представляет класс, предназначенный для загрузки ответа от HTTP-сервера.
    /// </summary>
    #if DEBUG
    [DebuggerDisplay("ToString() disabled in debug mode")]
    #endif
    public sealed class HttpResponse
    {
        #region Классы (закрытые)

        // Обёртка для массива байтов.
        // Указывает реальное количество байтов содержащихся в массиве.
        private sealed class BytesWrapper
        {
            public int Length { get; set; }

            public byte[] Value { get; set; }
        }

        // Данный класс используется для загрузки начальных данных.
        // Но он также используется и для загрузки тела сообщения, точнее, из него просто выгружается остаток данных, полученный при загрузки начальных данных.
        private sealed class ReceiverHelper
        {
            private const int InitialLineSize = 1000;


            #region Поля (закрытые)

            private Stream _stream;

            private readonly byte[] _buffer;
            private readonly int _bufferSize;

            private int _linePosition;
            private byte[] _lineBuffer = new byte[InitialLineSize];

            #endregion


            #region Свойства (открытые)

            public bool HasData => Length - Position != 0;

            private int Length { get; set; }

            public int Position { get; private set; }

            #endregion


            public ReceiverHelper(int bufferSize)
            {
                _bufferSize = bufferSize;
                _buffer = new byte[_bufferSize];
            }


            #region Методы (открытые)

            public void Init(Stream stream)
            {
                _stream = stream;
                _linePosition = 0;

                Length = 0;
                Position = 0;
            }

            public string ReadLine()
            {
                _linePosition = 0;

                while (true)
                {
                    if (Position == Length)
                    {
                        Position = 0;
                        Length = _stream.Read(_buffer, 0, _bufferSize);

                        if (Length == 0)
                            break;
                    }

                    byte b = _buffer[Position++];

                    _lineBuffer[_linePosition++] = b;

                    // Если считан символ '\n'.
                    if (b == 10)
                        break;

                    // Если не достигнут максимальный предел размера буфера линии.
                    if (_linePosition != _lineBuffer.Length)
                        continue;

                    // Увеличиваем размер буфера линии в два раза.
                    var newLineBuffer = new byte[_lineBuffer.Length * 2];

                    _lineBuffer.CopyTo(newLineBuffer, 0);
                    _lineBuffer = newLineBuffer;
                }

                return Encoding.ASCII.GetString(_lineBuffer, 0, _linePosition);
            }

            public int Read(byte[] buffer, int index, int length)
            {
                int curLength = Length - Position;

                if (curLength > length)
                    curLength = length;

                Array.Copy(_buffer, Position, buffer, index, curLength);

                Position += curLength;

                return curLength;
            }

            #endregion
        }

        // Данный класс используется при загрузки сжатых данных.
        // Он позволяет определить точное количество считаных байт (сжатых данных).
        // Это нужно, так как потоки для считывания сжатых данных сообщают количество байт уже преобразованных данных.
        private sealed class ZipWrapperStream : Stream
        {
            #region Поля (закрытые)

            private readonly Stream _baseStream;
            private readonly ReceiverHelper _receiverHelper;

            #endregion


            #region Свойства (открытые)

            private int BytesRead { get; set; }

            public int TotalBytesRead { get; set; }

            public int LimitBytesRead { private get; set; }

            #region Переопределённые

            public override bool CanRead => _baseStream.CanRead;

            public override bool CanSeek => _baseStream.CanSeek;

            public override bool CanTimeout => _baseStream.CanTimeout;

            public override bool CanWrite => _baseStream.CanWrite;

            public override long Length => _baseStream.Length;

            public override long Position
            {
                get => _baseStream.Position;
                set => _baseStream.Position = value;
            }

            #endregion

            #endregion


            public ZipWrapperStream(Stream baseStream, ReceiverHelper receiverHelper)
            {
                _baseStream = baseStream;
                _receiverHelper = receiverHelper;
            }


            #region Методы (открытые)

            public override void Flush() => _baseStream.Flush();

            public override void SetLength(long value) => _baseStream.SetLength(value);

            public override long Seek(long offset, SeekOrigin origin)
            {
                return _baseStream.Seek(offset, origin);
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                // Если установлен лимит на количество считанных байт.
                if (LimitBytesRead != 0)
                {
                    int length = LimitBytesRead - TotalBytesRead;

                    // Если лимит достигнут.
                    if (length == 0)
                        return 0;

                    if (length > buffer.Length)
                        length = buffer.Length;

                    BytesRead = _receiverHelper.HasData 
                        ? _receiverHelper.Read(buffer, offset, length) 
                        : _baseStream.Read(buffer, offset, length);
                }
                else
                {
                    BytesRead = _receiverHelper.HasData 
                        ? _receiverHelper.Read(buffer, offset, count) 
                        : _baseStream.Read(buffer, offset, count);
                }

                TotalBytesRead += BytesRead;

                return BytesRead;
            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                _baseStream.Write(buffer, offset, count);
            }

            #endregion
        }

        #endregion


        #region Статические поля (закрытые)

        private static readonly byte[] OpenHtmlSignature = Encoding.ASCII.GetBytes("<html");
        private static readonly byte[] CloseHtmlSignature = Encoding.ASCII.GetBytes("</html>");

        private static readonly Regex KeepAliveTimeoutRegex = new Regex(
            @"timeout(|\s+)=(|\s+)(?<value>\d+)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex KeepAliveMaxRegex = new Regex(
            @"max(|\s+)=(|\s+)(?<value>\d+)",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex ContentCharsetRegex = new Regex(
           @"charset(|\s+)=(|\s+)(?<value>[a-z,0-9,-]+)",
           RegexOptions.Compiled | RegexOptions.IgnoreCase);

        #endregion


        #region Поля (закрытые)

        private readonly HttpRequest _request;
        private ReceiverHelper _receiverHelper;

        private readonly Dictionary<string, string> _headers =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        // Lazy redirect headers
        public Dictionary<string, string> MiddleHeaders => _middleHeaders ??
            (_middleHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase));

        private Dictionary<string, string> _middleHeaders;


        private string _loadedMessageBody;
        //private MemoryStream _loadedMessageBody;
        #endregion


        #region Свойства (открытые)

        /// <summary>
        /// Возвращает значение, указывающие, произошла ли ошибка во время получения ответа от HTTP-сервера.
        /// </summary>
        public bool HasError { get; private set; }

        /// <summary>
        /// Возвращает значение, указывающие, загружено ли тело сообщения.
        /// </summary>
        public bool MessageBodyLoaded { get; private set; }

        /// <summary>
        /// Возвращает значение, указывающие, успешно ли выполнен запрос (код ответа = 200 OK). 
        /// </summary>
        // ReSharper disable once UnusedMember.Global
        // ReSharper disable once InconsistentNaming
        public bool IsOK => StatusCode == HttpStatusCode.OK;

        /// <summary>
        /// Возвращает значение, указывающие, имеется ли переадресация.
        /// </summary>
        public bool HasRedirect
        {
            get {
                int numStatusCode = (int)StatusCode;

                return numStatusCode >= 300 && numStatusCode < 400 
                    || _headers.ContainsKey("Location")
                    || _headers.ContainsKey("Redirect-Location");
            }
        }


        /// <summary>
        /// Возвращает значение, указывающее, была ли переадресация на протокол отличный от HTTP или HTTPS.
        /// </summary>
        public bool HasExternalRedirect =>
            HasRedirect && RedirectAddress != null &&
            !RedirectAddress.Scheme.Equals("http", StringComparison.InvariantCultureIgnoreCase) &&
            !RedirectAddress.Scheme.Equals("https", StringComparison.InvariantCultureIgnoreCase);

        /// <summary>
        /// Возвращает количество попыток переподключения.
        /// </summary>
        public int ReconnectCount { get; internal set; }

        #region Основные данные

        /// <summary>
        /// Возвращает URI интернет-ресурса, который фактически отвечал на запрос.
        /// </summary>
        public Uri Address { get; private set; }

        /// <summary>
        /// Возвращает HTTP-метод, используемый для получения ответа.
        /// </summary>
        public HttpMethod Method { get; private set; }

        /// <summary>
        /// Возвращает версию HTTP-протокола, используемую в ответе.
        /// </summary>
        public Version ProtocolVersion { get; private set; }

        /// <summary>
        /// Возвращает код состояния ответа.
        /// </summary>
        public HttpStatusCode StatusCode { get; private set; }

        /// <summary>
        /// Возвращает адрес переадресации.
        /// </summary>
        /// <returns>Адрес переадресации, иначе <see langword="null"/>.</returns>
        public Uri RedirectAddress { get; private set; }

        #endregion

        #region HTTP-заголовки

        /// <summary>
        /// Возвращает кодировку тела сообщения.
        /// </summary>
        /// <value>Кодировка тела сообщения, если соответствующий заголовок задан, иначе значение заданное в <see cref="HttpRequest"/>. Если и оно не задано, то значение <see cref="System.Text.Encoding.Default"/>.</value>
        public Encoding CharacterSet { get; private set; }

        /// <summary>
        /// Возвращает длину тела сообщения.
        /// </summary>
        /// <value>Длина тела сообщения, если соответствующий заголовок задан, иначе -1.</value>
        public long ContentLength { get; private set; }

        /// <summary>
        /// Возвращает тип содержимого ответа.
        /// </summary>
        /// <value>Тип содержимого ответа, если соответствующий заголовок задан, иначе пустая строка.</value>
        public string ContentType { get; private set; }

        /// <summary>
        /// Возвращает значение HTTP-заголовка 'Location'.
        /// </summary>
        /// <returns>Значение заголовка, если такой заголовок задан, иначе пустая строка.</returns>
        // ReSharper disable once UnusedMember.Global
        public string Location => this["Location"];

        /// <summary>
        /// Возвращает куки, образовавшиеся в результате запроса, или установленные в <see cref="HttpRequest"/>.
        /// </summary>
        /// <remarks>Если куки были установлены в <see cref="HttpRequest"/> и значение свойства <see cref="CookieStorage.IsLocked"/> равно <see langword="true"/>, то будут созданы новые куки.</remarks>
        public CookieStorage Cookies { get; private set; }

        /// <summary>
        /// Возвращает время простаивания постоянного соединения в миллисекундах.
        /// </summary>
        /// <value>Значение по умолчанию - <see langword="null"/>.</value>
        public int? KeepAliveTimeout { get; private set; }

        /// <summary>
        /// Возвращает максимально допустимое количество запросов для одного соединения.
        /// </summary>
        /// <value>Значение по умолчанию - <see langword="null"/>.</value>
        public int? MaximumKeepAliveRequests { get; private set; }

        #endregion

        #endregion


        #region Индексаторы (открытые)

        /// <summary>
        /// Возвращает значение HTTP-заголовка.
        /// </summary>
        /// <param name="headerName">Название HTTP-заголовка.</param>
        /// <value>Значение HTTP-заголовка, если он задан, иначе пустая строка.</value>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="headerName"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="headerName"/> является пустой строкой.</exception>
        public string this[string headerName]
        {
            get
            {
                #region Проверка параметра

                if (headerName == null)
                    throw new ArgumentNullException(nameof(headerName));

                if (headerName.Length == 0)
                    throw ExceptionHelper.EmptyString(nameof(headerName));

                #endregion

                if (!_headers.TryGetValue(headerName, out string value))
                    value = string.Empty;

                return value;
            }
        }

        /// <summary>
        /// Возвращает значение HTTP-заголовка.
        /// </summary>
        /// <param name="header">HTTP-заголовок.</param>
        /// <value>Значение HTTP-заголовка, если он задан, иначе пустая строка.</value>
        public string this[HttpHeader header] => this[Http.Headers[header]];

        #endregion


        internal HttpResponse(HttpRequest request)
        {
            _request = request;

            ContentLength = -1;
            ContentType = string.Empty;
        }


        #region Методы (открытые)

        /// <summary>
        /// Загружает тело сообщения и возвращает его в виде массива байтов.
        /// </summary>
        /// <returns>Если тело сообщения отсутствует, или оно уже было загружено, то будет возвращён пустой массив байтов.</returns>
        /// <exception cref="System.InvalidOperationException">Вызов метода из ошибочного ответа.</exception>
        /// <exception cref="HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public byte[] ToBytes()
        {
            #region Проверка состояния

            if (HasError)
            {
                throw new InvalidOperationException(
                    Resources.InvalidOperationException_HttpResponse_HasError);
            }

            #endregion

            if (MessageBodyLoaded)
                return new byte[0];

            using (var memoryStream = new MemoryStream())
            {
                memoryStream.SetLength(ContentLength == -1 ? 0 : ContentLength);

                try
                {
                    var source = GetMessageBodySource();

                    foreach (var bytes in source)
                        memoryStream.Write(bytes.Value, 0, bytes.Length);
                }
                catch (Exception ex)
                {
                    HasError = true;

                    if (ex is IOException || ex is InvalidOperationException)
                        throw NewHttpException(Resources.HttpException_FailedReceiveMessageBody, ex);

                    throw;
                }

                if (ConnectionClosed())
                    _request?.Dispose();

                MessageBodyLoaded = true;

                return memoryStream.ToArray();
            }
        }

        /// <summary>
        /// Загружает тело сообщения и возвращает его в виде строки.
        /// </summary>
        /// <returns>Если тело сообщения отсутствует, или оно уже было загружено, то будет возвращена пустая строка.</returns>
        /// <exception cref="System.InvalidOperationException">Вызов метода из ошибочного ответа.</exception>
        /// <exception cref="HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        public override string ToString()
        {
            #region Проверка состояния

            if (HasError)
                return string.Empty; //throw new InvalidOperationException(Resources.InvalidOperationException_HttpResponse_HasError);

            #endregion

            if (MessageBodyLoaded)
                return _loadedMessageBody;

            var memoryStream = new MemoryStream();
            memoryStream.SetLength(ContentLength == -1 ? 0 : ContentLength);

            try
            {    
                var source = GetMessageBodySource();

                foreach (var bytes in source)
                    memoryStream.Write(bytes.Value, 0, bytes.Length);
            }
            catch (Exception ex)
            {
                HasError = true;

                if (ex is IOException || ex is InvalidOperationException)
                    throw NewHttpException(Resources.HttpException_FailedReceiveMessageBody, ex);

                throw;
            }

            if (ConnectionClosed())
                _request.Dispose();

            MessageBodyLoaded = true;

            _loadedMessageBody = CharacterSet.GetString(
                memoryStream.GetBuffer(), 0, (int)memoryStream.Length);

            memoryStream.Dispose(); // TODO: case to an error?

            return _loadedMessageBody;
        }

        /// <summary>
        /// Загружает тело сообщения и сохраняет его в новый файл по указанному пути. Если файл уже существует, то он будет перезаписан.
        /// </summary>
        /// <param name="path">Путь к файлу, в котором будет сохранено тело сообщения.</param>
        /// <exception cref="System.InvalidOperationException">Вызов метода из ошибочного ответа.</exception>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="path"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="path"/> является пустой строкой, содержит только пробелы или содержит недопустимые символы.</exception>
        /// <exception cref="System.IO.PathTooLongException">Указанный путь, имя файла или и то и другое превышает наибольшую возможную длину, определенную системой. Например, для платформ на основе Windows длина пути не должна превышать 248 знаков, а имена файлов не должны содержать более 260 знаков.</exception>
        /// <exception cref="System.IO.FileNotFoundException">Значение параметра <paramref name="path"/> указывает на несуществующий файл.</exception>
        /// <exception cref="System.IO.DirectoryNotFoundException">Значение параметра <paramref name="path"/> указывает на недопустимый путь.</exception>
        /// <exception cref="System.IO.IOException">При открытии файла возникла ошибка ввода-вывода.</exception>
        /// <exception cref="System.Security.SecurityException">Вызывающий оператор не имеет необходимого разрешения.</exception>
        /// <exception cref="System.UnauthorizedAccessException">
        /// Операция чтения файла не поддерживается на текущей платформе.
        /// -или-
        /// Значение параметра <paramref name="path"/> определяет каталог.
        /// -или-
        /// Вызывающий оператор не имеет необходимого разрешения.
        /// </exception>
        /// <exception cref="HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public void ToFile(string path)
        {
            #region Проверка состояния

            if (HasError)
            {
                throw new InvalidOperationException(
                    Resources.InvalidOperationException_HttpResponse_HasError);
            }

            #endregion

            #region Проверка параметров

            if (path == null)
                throw new ArgumentNullException(nameof(path));

            #endregion

            if (MessageBodyLoaded)
                return;

            try
            {
                using (var fileStream = new FileStream(path, FileMode.Create))
                {
                    var source = GetMessageBodySource();

                    foreach (var bytes in source)
                        fileStream.Write(bytes.Value, 0, bytes.Length);
                }
            }
            #region Catch's

            catch (ArgumentException ex)
            {
                throw ExceptionHelper.WrongPath(nameof(path), ex);
            }
            catch (NotSupportedException ex)
            {
                throw ExceptionHelper.WrongPath(nameof(path), ex);
            }
            catch (Exception ex)
            {
                HasError = true;

                if (ex is IOException || ex is InvalidOperationException)
                    throw NewHttpException(Resources.HttpException_FailedReceiveMessageBody, ex);

                throw;
            }

            #endregion

            if (ConnectionClosed())
                _request.Dispose();

            MessageBodyLoaded = true;
        }

        /// <summary>
        /// Загружает тело сообщения и возвращает его в виде потока байтов из памяти.
        /// </summary>
        /// <returns>Если тело сообщения отсутствует, или оно уже было загружено, то будет возвращено значение <see langword="null"/>.</returns>
        /// <exception cref="System.InvalidOperationException">Вызов метода из ошибочного ответа.</exception>
        /// <exception cref="HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        // ReSharper disable once UnusedMember.Global
        public MemoryStream ToMemoryStream()
        {
            #region Проверка состояния

            if (HasError)
            {
                throw new InvalidOperationException(
                    Resources.InvalidOperationException_HttpResponse_HasError);
            }

            #endregion

            if (MessageBodyLoaded)
                return null;

            var memoryStream = new MemoryStream();
            memoryStream.SetLength(ContentLength == -1 ? 0 : ContentLength);

            try
            {
                var source = GetMessageBodySource();

                foreach (var bytes in source)
                    memoryStream.Write(bytes.Value, 0, bytes.Length);
            }
            catch (Exception ex)
            {
                HasError = true;

                if (ex is IOException || ex is InvalidOperationException)
                    throw NewHttpException(Resources.HttpException_FailedReceiveMessageBody, ex);

                throw;
            }

            if (ConnectionClosed())
                _request.Dispose();

            MessageBodyLoaded = true;
            memoryStream.Position = 0;
            return memoryStream;
        }

        /// <summary>
        /// Пропускает тело сообщения. Данный метод следует вызвать, если не требуется тело сообщения.
        /// </summary>
        /// <exception cref="System.InvalidOperationException">Вызов метода из ошибочного ответа.</exception>
        /// <exception cref="HttpException">Ошибка при работе с HTTP-протоколом.</exception>
        public void None()
        {
            #region Проверка состояния

            if (HasError)
            {
                throw new InvalidOperationException(
                    Resources.InvalidOperationException_HttpResponse_HasError);
            }

            #endregion

            if (MessageBodyLoaded)
                return;

            if (ConnectionClosed())
                _request.Dispose();
            else
            {
                try
                {
                    var source = GetMessageBodySource();

                    foreach (var unused in source) { }
                }
                catch (Exception ex)
                {
                    HasError = true;

                    if (ex is IOException || ex is InvalidOperationException)
                        throw NewHttpException(Resources.HttpException_FailedReceiveMessageBody, ex);

                    throw;
                }
            }

            MessageBodyLoaded = true;
        }

        #region Работа с куки

        /// <summary>
        /// Определяет, содержатся ли указанные куки по указанному веб-адресу.
        /// </summary>
        /// <param name="url">Адрес ресурса.</param>
        /// <param name="name">Название куки.</param>
        /// <returns>Значение <see langword="true"/>, если указанные куки содержатся, иначе значение <see langword="false"/>.</returns>
        public bool ContainsCookie(string url, string name)
        {
            return Cookies != null && Cookies.Contains(url, name);
        }

        /// <inheritdoc cref="ContainsCookie(string,string)"/>
        /// <param name="uri">Адрес для куки</param>
        public bool ContainsCookie(Uri uri, string name)
        {
            return Cookies != null && Cookies.Contains(uri, name);
        }

        /// <inheritdoc cref="ContainsCookie(string,string)"/>
        /// <summary>
        /// Определяет, содержатся ли указанные куки по адресу из ответа.
        /// </summary>
        // ReSharper disable once UnusedMember.Global
        public bool ContainsCookie(string name)
        {
            return Cookies != null && Cookies.Contains(HasRedirect && !HasExternalRedirect ? RedirectAddress : Address, name);
        }
        
        #endregion

        #region Работа с заголовками

        /// <summary>
        /// Определяет, содержится ли указанный HTTP-заголовок.
        /// </summary>
        /// <param name="headerName">Название HTTP-заголовка.</param>
        /// <returns>Значение <see langword="true"/>, если указанный HTTP-заголовок содержится, иначе значение <see langword="false"/>.</returns>
        /// <exception cref="System.ArgumentNullException">Значение параметра <paramref name="headerName"/> равно <see langword="null"/>.</exception>
        /// <exception cref="System.ArgumentException">Значение параметра <paramref name="headerName"/> является пустой строкой.</exception>
        public bool ContainsHeader(string headerName)
        {
            #region Проверка параметров

            if (headerName == null)
                throw new ArgumentNullException(nameof(headerName));

            if (headerName.Length == 0)
                throw ExceptionHelper.EmptyString(nameof(headerName));

            #endregion

            return _headers.ContainsKey(headerName);
        }

        /// <summary>
        /// Определяет, содержится ли указанный HTTP-заголовок.
        /// </summary>
        /// <param name="header">HTTP-заголовок.</param>
        /// <returns>Значение <see langword="true"/>, если указанный HTTP-заголовок содержится, иначе значение <see langword="false"/>.</returns>
        // ReSharper disable once UnusedMember.Global
        public bool ContainsHeader(HttpHeader header)
        {
            return ContainsHeader(Http.Headers[header]);
        }

        /// <summary>
        /// Возвращает перечисляемую коллекцию HTTP-заголовков.
        /// </summary>
        /// <returns>Коллекция HTTP-заголовков.</returns>
        // ReSharper disable once UnusedMember.Global
        public Dictionary<string, string>.Enumerator EnumerateHeaders()
        {
            return _headers.GetEnumerator();
        }

        #endregion

        #endregion


        // Загружает ответ и возвращает размер ответа в байтах.
        internal long LoadResponse(HttpMethod method, bool trackMiddleHeaders)
        {
            Method = method;
            Address = _request.Address;

            HasError = false;
            MessageBodyLoaded = false;
            KeepAliveTimeout = null;
            MaximumKeepAliveRequests = null;

            if (trackMiddleHeaders && _headers.Count > 0)
            {
                foreach (string key in _headers.Keys)
                    MiddleHeaders[key] = _headers[key];
            }
            _headers.Clear();

            if (_request.UseCookies)
            {
                Cookies = _request.Cookies != null && !_request.Cookies.IsLocked
                    ? _request.Cookies
                    : new CookieStorage(ignoreInvalidCookie: _request.IgnoreInvalidCookie);
            }

            if (_receiverHelper == null)
                _receiverHelper = new ReceiverHelper(_request.TcpClient.ReceiveBufferSize);

            _receiverHelper.Init(_request.ClientStream);

            try
            {
                ReceiveStartingLine();
                ReceiveHeaders();

                RedirectAddress = GetLocation();
                CharacterSet = GetCharacterSet();
                ContentLength = GetContentLength();
                ContentType = GetContentType();

                KeepAliveTimeout = GetKeepAliveTimeout();
                MaximumKeepAliveRequests = GetKeepAliveMax();
            }
            catch (Exception ex)
            {
                HasError = true;

                if (ex is IOException)
                    throw NewHttpException(Resources.HttpException_FailedReceiveResponse, ex);

                throw;
            }

            // Если пришёл ответ без тела сообщения.
            if (ContentLength == 0 ||
                Method == HttpMethod.HEAD ||
                StatusCode == HttpStatusCode.Continue ||
                StatusCode == HttpStatusCode.NoContent ||
                StatusCode == HttpStatusCode.NotModified)
            {
                _loadedMessageBody = string.Empty;
                MessageBodyLoaded = true;
            }

            long responseSize = _receiverHelper.Position;

            if (ContentLength > 0)
                responseSize += ContentLength;

            return responseSize;
        }


        #region Методы (закрытые)

        #region Загрузка начальных данных

        private void ReceiveStartingLine()
        {
            string startingLine;

            while (true)
            {
                startingLine = _receiverHelper.ReadLine();

                if (startingLine.Length == 0)
                {
                    var exception = NewHttpException(Resources.HttpException_ReceivedEmptyResponse);
                    exception.EmptyMessageBody = true;

                    throw exception;
                }
                if (startingLine != Http.NewLine)
                    break;
            }

            string version = startingLine.Substring("HTTP/", " ");
            string statusCode = startingLine.Substring(" ", " ");

            // Если сервер не возвращает Reason Phrase
            if (string.IsNullOrEmpty(statusCode))
                statusCode = startingLine.Substring(" ", Http.NewLine);

            if (string.IsNullOrEmpty(version) || string.IsNullOrEmpty(statusCode))
                throw NewHttpException(Resources.HttpException_ReceivedEmptyResponse);

            ProtocolVersion = Version.Parse(version);

            StatusCode = (HttpStatusCode)Enum.Parse(typeof(HttpStatusCode), statusCode);
        }
        
        private void ReceiveHeaders()
        {
            while (true)
            {
                string header = _receiverHelper.ReadLine();

                // Если достигнут конец заголовков.
                if (header == Http.NewLine)
                    return;

                // Ищем позицию между именем и значением заголовка.
                int separatorPos = header.IndexOf(':');

                if (separatorPos == -1)
                {
                    string message = string.Format(
                        Resources.HttpException_WrongHeader, header, Address.Host);

                    throw NewHttpException(message);
                }

                string headerName = header.Substring(0, separatorPos);
                string headerValue = header.Substring(separatorPos + 1).Trim(' ', '\t', '\r', '\n');

                if (headerName.Equals("Set-Cookie", StringComparison.OrdinalIgnoreCase))
                    ParseCookieFromHeader(headerValue);
                else
                    _headers[headerName] = headerValue;
            }
        }

        #endregion

        #region Ручной разбор Cookie с расширенными атрибутами

        private void ParseCookieFromHeader(string headerValue)
        {
            if (!_request.UseCookies)
                return;

            Cookies.Set(_request.Address, headerValue);
        }

        #endregion

        #region Загрузка тела сообщения

        // ReSharper disable once ReturnTypeCanBeEnumerable.Local
        private IEnumerable<BytesWrapper> GetMessageBodySource()
        {
            var result = _headers.ContainsKey("Content-Encoding") && _headers["Content-Encoding"].Equals("gzip", StringComparison.OrdinalIgnoreCase)
                ? GetMessageBodySourceZip()
                : GetMessageBodySourceStd();

            return result; // .ToArray(); - it will break Chunked requests.
        }

        // Загрузка обычных данных.
        private IEnumerable<BytesWrapper> GetMessageBodySourceStd()
        {
            return _headers.ContainsKey("Transfer-Encoding")
                ? ReceiveMessageBodyChunked()
                : ContentLength != -1 ? ReceiveMessageBody(ContentLength) : ReceiveMessageBody(_request.ClientStream);
        }

        // Загрузка сжатых данных.
        private IEnumerable<BytesWrapper> GetMessageBodySourceZip()
        {
            if (_headers.ContainsKey("Transfer-Encoding"))
                return ReceiveMessageBodyChunkedZip();

            if (ContentLength != -1)
                return ReceiveMessageBodyZip(ContentLength);

            var streamWrapper = new ZipWrapperStream(
                _request.ClientStream, _receiverHelper);

            return ReceiveMessageBody(GetZipStream(streamWrapper));
        }

        private static byte[] GetResponse(Stream stream)
        {
            using (var memoryStream = new MemoryStream())
            {
                stream.CopyTo(memoryStream);
                return memoryStream.ToArray();
            }
        }

        // Загрузка тела сообщения неизвестной длины.
        private static IEnumerable<BytesWrapper> ReceiveMessageBody(Stream stream)
        {
            // It's a fix of response get stuck response issue #83: https://github.com/csharp-leaf/Leaf.xNet/issues/83
            var bytesWrapper = new BytesWrapper();
            var responseBytes = GetResponse(stream);
            bytesWrapper.Value = responseBytes;
            bytesWrapper.Length = responseBytes.Length;
            return new[] { bytesWrapper };
        }

        /*
        private IEnumerable<BytesWrapper> ReceiveMessageBody(Stream stream)
        {
            var bytesWrapper = new BytesWrapper();

            int bufferSize = _request.TcpClient.ReceiveBufferSize;
            var buffer = new byte[bufferSize];

            bytesWrapper.Value = buffer;

            int begBytesRead = 0;

            // Считываем начальные данные из тела сообщения.
            if (stream is GZipStream || stream is DeflateStream)
                begBytesRead = stream.Read(buffer, 0, bufferSize);
            else
            {
                if (_receiverHelper.HasData)
                    begBytesRead = _receiverHelper.Read(buffer, 0, bufferSize);

                if (begBytesRead < bufferSize)
                    begBytesRead += stream.Read(buffer, begBytesRead, bufferSize - begBytesRead);
            }

            // Возвращаем начальные данные.
            bytesWrapper.Length = begBytesRead;
            yield return bytesWrapper;

            // Проверяем, есть ли открывающий тег '<html'.
            // Если есть, то считываем данные то тех пор, пока не встретим закрывающий тек '</html>'.
            bool isHtml = FindSignature(buffer, begBytesRead, OpenHtmlSignature);

            if (isHtml)
            {
                bool found = FindSignature(buffer, begBytesRead, CloseHtmlSignature);

                // Проверяем, есть ли в начальных данных закрывающий тег.
                if (found)
                    yield break;
            }

            while (true)
            {
                int bytesRead = stream.Read(buffer, 0, bufferSize);

                // Если тело сообщения представляет HTML.
                if (isHtml)
                {
                    if (bytesRead == 0)
                    {
                        WaitData();
                        continue;
                    }

                    bool found = FindSignature(buffer, bytesRead, CloseHtmlSignature);

                    if (found)
                    {
                        bytesWrapper.Length = bytesRead;
                        yield return bytesWrapper;

                        yield break;
                    }
                }
                else if (bytesRead == 0)
                    yield break;

                bytesWrapper.Length = bytesRead;
                yield return bytesWrapper;
            }
        }
        */

        // Загрузка тела сообщения известной длины.
        private IEnumerable<BytesWrapper> ReceiveMessageBody(long contentLength)
        {
            var stream = _request.ClientStream;
            var bytesWrapper = new BytesWrapper();

            int bufferSize = _request.TcpClient.ReceiveBufferSize;
            var buffer = new byte[bufferSize];

            bytesWrapper.Value = buffer;

            int totalBytesRead = 0;

            while (totalBytesRead != contentLength)
            {
                int bytesRead = _receiverHelper.HasData ? _receiverHelper.Read(buffer, 0, bufferSize) : stream.Read(buffer, 0, bufferSize);

                if (bytesRead == 0)
                    WaitData();
                else
                {
                    totalBytesRead += bytesRead;

                    bytesWrapper.Length = bytesRead;
                    yield return bytesWrapper;
                }
            }
        }

        // Загрузка тела сообщения частями.
        private IEnumerable<BytesWrapper> ReceiveMessageBodyChunked()
        {
            var stream = _request.ClientStream;
            var bytesWrapper = new BytesWrapper();

            int bufferSize = _request.TcpClient.ReceiveBufferSize;
            var buffer = new byte[bufferSize];

            bytesWrapper.Value = buffer;

            while (true)
            {
                string line = _receiverHelper.ReadLine();

                // Если достигнут конец блока.
                if (line == Http.NewLine)
                    continue;

                line = line.Trim(' ', '\r', '\n');

                // Если достигнут конец тела сообщения.
                if (line == string.Empty)
                    yield break;

                int blockLength;
                int totalBytesRead = 0;

                #region Задаём длину блока

                try
                {
                    blockLength = Convert.ToInt32(line, 16);
                }
                catch (Exception ex)
                {
                    if (ex is FormatException || ex is OverflowException)
                    {
                        throw NewHttpException(string.Format(
                            Resources.HttpException_WrongChunkedBlockLength, line), ex);
                    }

                    throw;
                }

                #endregion

                // Если достигнут конец тела сообщения.
                if (blockLength == 0)
                    yield break;

                while (totalBytesRead != blockLength)
                {
                    int length = blockLength - totalBytesRead;

                    if (length > bufferSize)
                        length = bufferSize;

                    int bytesRead = _receiverHelper.HasData 
                        ? _receiverHelper.Read(buffer, 0, length) 
                        : stream.Read(buffer, 0, length);

                    if (bytesRead == 0)
                        WaitData();
                    else
                    {
                        totalBytesRead += bytesRead;

                        bytesWrapper.Length = bytesRead;
                        yield return bytesWrapper;
                    }
                }
            }
        }

        private IEnumerable<BytesWrapper> ReceiveMessageBodyZip(long contentLength)
        {
            var bytesWrapper = new BytesWrapper();
            var streamWrapper = new ZipWrapperStream(
                _request.ClientStream, _receiverHelper);

            using (var stream = GetZipStream(streamWrapper))
            {
                int bufferSize = _request.TcpClient.ReceiveBufferSize;
                var buffer = new byte[bufferSize];

                bytesWrapper.Value = buffer;

                while (true)
                {
                    int bytesRead = stream.Read(buffer, 0, bufferSize);

                    if (bytesRead == 0)
                    {
                        if (streamWrapper.TotalBytesRead == contentLength)
                            yield break;

                        WaitData();

                        continue;
                    }

                    bytesWrapper.Length = bytesRead;
                    yield return bytesWrapper;
                }
            }
        }

        private IEnumerable<BytesWrapper> ReceiveMessageBodyChunkedZip()
        {
            var bytesWrapper = new BytesWrapper();
            var streamWrapper = new ZipWrapperStream
                (_request.ClientStream, _receiverHelper);

            using (var stream = GetZipStream(streamWrapper))
            {
                int bufferSize = _request.TcpClient.ReceiveBufferSize;
                var buffer = new byte[bufferSize];

                bytesWrapper.Value = buffer;

                while (true)
                {
                    string line = _receiverHelper.ReadLine();

                    // Если достигнут конец блока.
                    if (line == Http.NewLine)
                        continue;

                    line = line.Trim(' ', '\r', '\n');

                    // Если достигнут конец тела сообщения.
                    if (line == string.Empty)
                        yield break;

                    int blockLength;

                    #region Задаём длину блока

                    try
                    {
                        blockLength = Convert.ToInt32(line, 16);
                    }
                    catch (Exception ex)
                    {
                        if (ex is FormatException || ex is OverflowException)
                        {
                            throw NewHttpException(string.Format(
                                Resources.HttpException_WrongChunkedBlockLength, line), ex);
                        }

                        throw;
                    }

                    #endregion

                    // Если достигнут конец тела сообщения.
                    if (blockLength == 0)
                        yield break;

                    streamWrapper.TotalBytesRead = 0;
                    streamWrapper.LimitBytesRead = blockLength;

                    while (true)
                    {
                        int bytesRead = stream.Read(buffer, 0, bufferSize);

                        if (bytesRead == 0)
                        {
                            if (streamWrapper.TotalBytesRead == blockLength)
                                break;

                            WaitData();

                            continue;
                        }

                        bytesWrapper.Length = bytesRead;
                        yield return bytesWrapper;
                    }
                }
            }
        }

        #endregion

        #region Получение значения HTTP-заголовков

        private bool ConnectionClosed()
        {
            return _headers.ContainsKey("Connection") &&
                   _headers["Connection"].Equals("close", StringComparison.OrdinalIgnoreCase) ||
                   _headers.ContainsKey("Proxy-Connection") &&
                   _headers["Proxy-Connection"].Equals("close", StringComparison.OrdinalIgnoreCase);
        }

        private int? GetKeepAliveTimeout()
        {
            if (!_headers.ContainsKey("Keep-Alive"))
                return null;

            string header = _headers["Keep-Alive"];
            var match = KeepAliveTimeoutRegex.Match(header);

            if (match.Success)
                return int.Parse(match.Groups["value"].Value) * 1000; // В миллисекундах.

            return null;
        }

        private int? GetKeepAliveMax()
        {
            if (!_headers.ContainsKey("Keep-Alive"))
                return null;

            string header = _headers["Keep-Alive"];
            var match = KeepAliveMaxRegex.Match(header);

            if (match.Success)
                return int.Parse(match.Groups["value"].Value);

            return null;
        }

        private Uri GetLocation()
        {
            if (!_headers.TryGetValue("Location", out string location))
                _headers.TryGetValue("Redirect-Location", out location);

            if (string.IsNullOrEmpty(location))
                return null;

            var baseAddress = _request.Address;
            Uri.TryCreate(baseAddress, location, out var redirectAddress);

            return redirectAddress;
        }

        private Encoding GetCharacterSet()
        {
            if (!_headers.ContainsKey("Content-Type"))
                return _request.CharacterSet ?? Encoding.Default;

            string header = _headers["Content-Type"];
            var match = ContentCharsetRegex.Match(header);

            if (!match.Success)
                return _request.CharacterSet ?? Encoding.Default;

            var charset = match.Groups["value"];

            try
            {
                return Encoding.GetEncoding(charset.Value);
            }
            catch (ArgumentException)
            {
                return _request.CharacterSet ?? Encoding.Default;
            }
        }

        private long GetContentLength()
        {
            string contentLengthHeader = Http.Headers[HttpHeader.ContentLength];

            if (!_headers.ContainsKey(contentLengthHeader))
                return -1;

            if (!long.TryParse(_headers[contentLengthHeader], out long contentLength))
                throw new FormatException($"Invalid response header \"{contentLengthHeader}\" value");

            return contentLength;
        }

        private string GetContentType()
        {
            string contentTypeHeader = Http.Headers[HttpHeader.ContentType];

            if (!_headers.ContainsKey(contentTypeHeader))
                return string.Empty;

            string contentType = _headers[contentTypeHeader];

            // Ищем позицию, где заканчивается описание типа контента и начинается описание его параметров.
            int endTypePos = contentType.IndexOf(';');
            if (endTypePos != -1)
                contentType = contentType.Substring(0, endTypePos);
  
            return contentType;
        }

        #endregion

        private void WaitData()
        {
            int sleepTime = 0;
            int delay = _request.TcpClient.ReceiveTimeout < 10
                ? 10 
                : _request.TcpClient.ReceiveTimeout;

            while (!_request.ClientNetworkStream.DataAvailable)
            {
                if (sleepTime >= delay)
                    throw NewHttpException(Resources.HttpException_WaitDataTimeout);

                sleepTime += 10;
                Thread.Sleep(10);
            }
        }

        private Stream GetZipStream(Stream stream)
        {
            string contentEncoding = _headers[Http.Headers[HttpHeader.ContentEncoding]].ToLower();

            return new string[]
            {
                "gzip",
                "deflate"
            }.FirstOrDefault(x => contentEncoding.Contains(x)) switch
            {
                "gzip" => new GZipStream(stream, CompressionMode.Decompress, true),
                "deflate" => new DeflateStream(stream, CompressionMode.Decompress, true),
                _ => throw new InvalidOperationException(string.Format(Resources.InvalidOperationException_NotSupportedEncodingFormat, contentEncoding))
            };
        }

        // ReSharper disable once SuggestBaseTypeForParameter        
        private static bool FindSignature(byte[] source, int sourceLength,
            // ReSharper disable once SuggestBaseTypeForParameter
            byte[] signature)
        {
            int length = sourceLength - signature.Length + 1;

            for (int sourceIndex = 0; sourceIndex < length; ++sourceIndex)
            {
                for (int signatureIndex = 0; signatureIndex < signature.Length; ++signatureIndex)
                {
                    byte sourceByte = source[signatureIndex + sourceIndex];
                    char sourceChar = (char)sourceByte;

                    if (char.IsLetter(sourceChar))
                        sourceChar = char.ToLower(sourceChar);

                    sourceByte = (byte)sourceChar;

                    if (sourceByte != signature[signatureIndex])
                        break;

                    if (signatureIndex == signature.Length - 1)
                        return true;
                }
            }

            return false;
        }

        private HttpException NewHttpException(string message, Exception innerException = null)
        {
            return new HttpException(string.Format(message, Address.Host),
                HttpExceptionStatus.ReceiveFailure, HttpStatusCode.None, innerException);
        }

        #endregion
    }
}

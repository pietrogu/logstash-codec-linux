# encoding: utf-8
require "logstash/util/charset"
require "logstash/codecs/base"

class LogStash::Codecs::Postfix < LogStash::Codecs::Base
  config_name "postfix"
  # Array con i nomi dei campi del log
  HEADER_FIELDS = ["Date","Host","Process","PID","Description"]
  
  # Regexp per individuare le coppie key/value nel messaggio
  KEY_PATTERN = /(?:\w+(?:\.[^\s]\w+[^\|\s\.\=\\]+)?(?==))/
  VALUE_PATTERN = /(?:\S|\s++(?!#{KEY_PATTERN}=))*/
  KEY_VALUE_SCANNER = /(#{KEY_PATTERN})=(#{VALUE_PATTERN})\s*/
  # Regexp per individuare il QUEUE ID e il Message Level
  QUEUE_REGEXP = /([A-F0-9]+\:|[A-F0-9]+\_[A-F0-9]+\:|NOQUEUE\:)/    
  MSG_LEVEL_REGEXP = /reject\:|warning\:|error\:|fatal\:|panic\:|statistics\:/
  # Regexp per trovare un escape character (backslash o uguale)
  VALUE_ESCAPE_CAPTURE = /\\([\\=])/
  # Regexp per trovare nelle key una sintassi simile a quella di un array
  KEY_ARRAY_CAPTURE = /^([^\[\]]+)((?:\[[0-9]+\])+)$/
  
  public
  def initialize(params={})
    super(params)
    # Input deve essere codificato in UTF-8
    @utf8_charset = LogStash::Util::Charset.new('UTF-8')
    @utf8_charset.logger = self.logger
  end
   
  # In questa sezione effettuiamo il parsing
  def decode(data, &block)
    # Creiamo l'evento
    event = LogStash::Event.new
    # Usiamo per il log la codifica UTF-8
    @utf8_charset.convert(data)
    # Se l'encoding non ha avuto successo non andiamo avanti nel parsing, nascerebbero errori
    fail('invalid byte sequence in UTF-8') unless data.valid_encoding?

    # Nel caso ci siano caratteri a delimitare l'inizio e alla fine del log, vengono rimossi
    if data[0] == "\""
      data = data[1..-2]
    end
    
    # Il log da parsare viene separato in due parti
    unprocessed_data = data.split(': ',2)
    header = unprocessed_data[0]
    # il gsub serve per evitare che in uscita vi siano "\" in corrispondenza dei doppi apici
    message = unprocessed_data[1].gsub(/["]/,'')
	
    # Lavoriamo sull'header per ricavare i diversi campi
    # La seguente parte di codice trova la data, valutando diversi formati
    date_rule = /\w{3}\s+\d{1,2}\s+\d{2,4}\s+\d{2}\:\d{2}\:\d{2}\s/
    date = header.scan(date_rule)
    if date == [] 
      date_rule = /\d{1,4}[\/-]\d{1,2}[\/-]\d{1,4}\s+\d{2}\:\d{2}\:\d{2}\s/ 	
      date = header.scan(date_rule)
      if date == []
        date_rule = /\w{3}\s+\d{1,2}\s+\d{2}\:\d{2}\:\d{2}\s/
	date = header.scan(date_rule)
      end
    end
    # Nell'evento settiamo la coppia header-valore trovata
    event.set(HEADER_FIELDS[0], date.join(" ").chomp(" "))
    
    # Eliminiamo la data dal messaggio da elaborare
    header.slice! date_rule
    # Leviamo le parentesi quadre per isolare il PID e separiamo gli elementi rimanenti, ponendoli in un array	
    header_array = header.gsub(/[\[\]]/," ").split(/ /)
    # Associamo le coppie campo/valore dell'header
    i = 1
    header_array.each do |fields|
	unless fields.nil? 
	event.set(HEADER_FIELDS[i], fields)
      end    
      i = i + 1
    end
    # Verifichiamo che il campo Process sia settato
    unless event.get('Process').nil?
    # Controlla il campo Process per capire se presenta un'info sul processo postfix
      if event.get('Process').include? 'postfix/'
        # Divide il campo Process usando rpartition, che separa rispetto all'ultima occorrenza 	
        split_process = event.get('Process').rpartition('/')
        # Prima parte: postfix
        event.set('Process', split_process[0])
        # Ultima parte: daemon postfix
	# (nota: in [1] si trova l'elemento di separazione, in questo caso lo slash) 
        event.set('Postfix_daemon',split_process[2])
      end
    end

    unless event.get('Host').nil?
    # Controlla il campo Host per vedere se presenta un carattere '<'
      if event.get('Host').include? '<'
        # Leva dal campo host il termine <.> 	
        clean_host = event.get('Host').gsub(/\<\d+\>/,'')
	# Aggiorno l'host 
        event.set('Host', clean_host)
      end
    end

    # Verifichiamo la presente di un Queue ID e lo scriviamo nell'evento 
    queue_id = message.scan(QUEUE_REGEXP)
    unless queue_id == []
      event.set("Queue_ID",queue_id.join("").chomp(":"))
      message.slice! QUEUE_REGEXP
    end
    # Verifichiamo la presenza di un Message Level e lo scriviamo nell'evento
    msg_level = message.scan(MSG_LEVEL_REGEXP)
    unless msg_level == []
      event.set("Message_Level",msg_level.join("").chomp(":"))
      message.slice! MSG_LEVEL_REGEXP
    end
    
    if message && message.include?('=') && event.get('Process').include?('postfix')
      # Leviamo dal messaggio eventuali caratteri di spazio alla fine e all'inizio
      message = message.strip
      # Ricaviamo le diverse coppie key/value del messaggio
      message.scan(KEY_VALUE_SCANNER) do |extension_field_key, raw_extension_field_value|
        # Evitiamo che key con sintassi simile a quella di un array possano creare errori
        extension_field_key = extension_field_key.sub(KEY_ARRAY_CAPTURE, '[\1]\2') if extension_field_key.end_with?(']')
        # Controlliamo la presenze di escape sequence e di altri simboli, poi rimuoviamo per evitare problemi in output
	extension_field_value = raw_extension_field_value.gsub(VALUE_ESCAPE_CAPTURE, '\1').gsub(/["]/,'').gsub("\\n",' ')
	# Nell'evento settiamo la coppia key-value trovata
        event.set(extension_field_key, extension_field_value.chomp(","))
      end
    # Rimuoviamo dal messaggio le coppie trovate
    message = message.gsub(KEY_VALUE_SCANNER,'')
    end
    
    # Inseriamo quello che rimane del messaggio in un campo dell'evento
    event.set(HEADER_FIELDS[-1], message.strip) unless message == "" 
    
    # Aggiungiamo il log non parsato
    event.set("RAW_MESSAGE", data)
    
    # Portiamo in uscita l'evento
    yield event

    # In caso di errore viene mostrato il seguente messaggio
    rescue => e
      @logger.error("Failed to decode Postfix payload. Generating failure event with payload in message field.", :error => e.message, :backtrace => e.backtrace, :data => data)
      yield LogStash::Event.new("message" => data, "tags" => ["_Postfixparsefailure"])
    end
end

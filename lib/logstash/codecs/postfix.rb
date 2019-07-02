# encoding: utf-8
require "logstash/util/charset"
require "logstash/codecs/base"

class LogStash::Codecs::Postfix < LogStash::Codecs::Base
  config_name "postfix"
  
  HEADER_FIELDS = ["Date","Host","Process","PID","Description"]    

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
    # Se l'encoding non ha avuto successo non andiamo avanti nel parsing, perchè nascerebbero errori
    fail('invalid byte sequence in UTF-8') unless data.valid_encoding?

    # Nel caso ci siano caratteri a delimitare l'inizio e alla fine del log, vengono rimossi
    if data[0] == "\""
      data = data[1..-2]
    end
    
    # Il log da parsare viene separato in due parti
    unprocessed_data = data.split(': ',2)
    header = unprocessed_data[0]
    # il gsub serve per evitare che in uscita vi siano "\" in corrispondenza dei doppi apici "
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
    # A questo punto nell'evento settiamo la coppia header-valore trovata
    event.set(HEADER_FIELDS[0], date.join(" ").chomp(" "))
    
    # Eliminiamo la data dai dati da elaborare
    header.slice! date_rule
    # Leviamo le parentesi quadre per isolare il PID e separiamo gli elementi rimanenti, ponendoli in un array	
    header_array = header.gsub(/[\[\]]/," ").split(/ /)
    # Associamo le coppie campo/valore dell'header
    i = 1      
    for j in 0..header_array.length	
      unless header_array[j].nil? 
	event.set(HEADER_FIELDS[i], header_array[j])
      end
    i = i + 1
    end

    # Verifichiamo che il campo Process sia settato
    unless event.get('Process').nil?
    # Controlla il campo Process per capire se è presente un'info sul processo postfix
      if event.get('Process').include? 'postfix/'
        # Separa il campo Process usando rpartition, che separa rispetto all'ultima occorrenza 	
        split_process = event.get('Process').rpartition('/')
        # La prima parte è postfix
        event.set('Process', split_process[0])
        # L'ultima parte è il daemon postfix (nota: in [1] c'è l'elemento di separazione, in questo caso lo slash) 
        event.set('Postfix_daemon',split_process[2])
      end
    end
    # Inseriamo il messaggio in coda all'evento
    event.set(HEADER_FIELDS[-1], message.strip)
	
    # Portiamo in uscita l'evento
    yield event

    # In caso di errore viene mostrato il seguente messaggio
    rescue => e
    @logger.error("Failed to decode Postfix payload. Generating failure event with payload in message field.", :error => e.message, :backtrace => e.backtrace, :data => data)
    yield LogStash::Event.new("message" => data, "tags" => ["_Postfixparsefailure"])
  end
end

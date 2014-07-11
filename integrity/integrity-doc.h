/**
 *
 * @defgroup integrity_loop_lib Lib
 * @ingroup integrity_loop
 *
 * @defgroup integrity_loop_main Main
 * @ingroup integrity_loop
 */

/**
  @page Integrity Loop
    @section s1 Abstract
    - Integrity Loop is responsible for the Grid Storage continuous integrity checking.
    - It uses informations stored in chunks file attributes to validate chunks integrity and informations stored in META2.
    - It is also used to rebuild META2 data that could have been lost after crash or bad manipulations.
 
    @section s2 Functionalities
      @subsection ss1 Chunk integrity check
      - Validates that chunk file size and md5 hash matches values stored in chunk file attributes hash and size.
      In case values do not match and since chunk file are the only components of Grid Storage which are not duplicated,
      values in attributes must be replaced by values determined from the chunk file.
 
      @subsection ss2 META2 data integrity check
      - Remove chunk entries which represents deleted chunks.
      - Remove uncommitted chunks and contents.
 
      @subsection ss3 META2 data reconstruction
      - Get broken containers/contents from local agent and try to rebuild data in META2 using chunk file attributes.
 
      @subsection ss4 Chunk and META2 data comparison
      - Compare data in chunk file attributes and data in META2.
      Write error log in case of mismatch cause IL can't decide alone which data is good and which is corrupted.
 
    @section s3 Execution
    - Integrity Loop runs continuously in a daemon mode.
    - Only one instance is running per server (it must handle all namespaces running on this server).
    - It automatically discovers RAWX and META2 services to check from the local agent.
    - Some tasks may be active only in a limited period of the day (during the night for ex) or of the week (during we)

    @section s4 Components
      @subsection ss5 RAWX and META2 services discoverer
        - service_discover.h
      @subsection ss6 volume parser
        - volume_parser.h
      @subsection ss7 RAWX checker callback
        - chunk_checker.h
      @subsection ss8 RAWX crawler callback
        - chunk_crawler.h
      @subsection ss9 META2 checker
        - meta2_checker.h
      @subsection ss10 Broken containers/contents listener
        - broken_listener.h
      @subsection ss11 META2 reconstructor
        - meta2_rebuilder.h
 */

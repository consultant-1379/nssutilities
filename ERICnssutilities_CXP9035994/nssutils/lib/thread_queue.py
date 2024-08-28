import datetime
import time
import Queue
from inspect import isfunction

# These modules are imported relatively from current python package i.e. lib
# and to avoid circular imports we cannot do from . import ...
import log
import exception
import timestamp
import multitasking
# End circular imports


class ThreadQueueEntry(object):

    def __init__(self, function, arg_list):
        """
        B{ThreadQueueEntry constructor}

        @type function: object
        @param function: The function reference object
        @type arg_list: list
        @param arg_list: List of arguments to pass to the function reference
        @rtype: void
        """

        self.function = function
        self.arg_list = arg_list
        self.result = None
        self.finished = False
        self.thread_id = None
        self.exception_raised = False
        self.exception_msg = None
        self.exception = None


class ThreadQueue(object):

    def __init__(self, work_items=None, num_workers=0, func_ref=None, args=None, task_join_timeout=None,
                 task_wait_timeout=None):
        """
        B{ThreadQueue constructor}

        @type work_items: list
        @param work_items: List of items (instances, nodes, node_objs, etc.) that will be passed to each invocation of the target function
        @type num_workers: int
        @param num_workers: The number of threads
        @type func_ref: function reference
        @param func_ref: Reference to the function to be spawned for each work item
        @type args: list
        @param args: Additional arguments to supply to the function reference after the mandatory work_item [optional]
        @type task_join_timeout: int
        @param task_join_timeout: Number of seconds to wait for workers
        @rtype: void
        """
        work_items = work_items or []

        self.work_items = work_items
        self.work_entries = []
        self.num_workers = num_workers
        self.func_ref = func_ref
        self.additional_args = args

        self.start_time = None
        self.elapsed_time = None

        self.exceptions_raised = 0
        self.exception_msgs = []
        self.exceptions = []

        # Validate the inputs
        self._validate_parameters()

        # Provision the work and done queues
        self.work_queue = Queue.Queue(len(work_items))
        self.done_queue = Queue.Queue(len(work_items))
        self.worker_pool = []
        self.task_join_timeout = task_join_timeout
        self.task_wait_timeout = task_wait_timeout

    def _validate_parameters(self):
        """
        B{Validates that all input parameters are valid}

        """

        if self.work_items is None or len(self.work_items) < 1:
            raise ValueError("Empty work_items list passed to thread queue; nothing to do...")

        if self.func_ref is None or not isfunction(self.func_ref):
            raise ValueError("Invalid function reference")

        self.num_workers = int(self.num_workers)

        # Make sure that the number of threads required to do the work is not more than the amount of work, if so reset it to the size of the queue
        if len(self.work_items) < self.num_workers:
            self.num_workers = len(self.work_items)

    def execute(self):
        """
        B{Executes the thread queue by creating a number of workers and having the workers work down the work queue until it is empty}

        """
        try:
            if not self.work_items:
                log.logger.debug('No work items to process. Will not proceed.')
                return

            # Start the clock and print out a message detailing what we are doing
            log.log_entry("{0}.{1}() [{2} threads for {3} work items]".format(self.func_ref.__module__, self.func_ref.__name__, self.num_workers, len(self.work_items)))
            self.start_time = timestamp.get_current_time()

            # Create a ThreadQueueEntry for each work item
            self._populate_work_queue()

            # Spawn the desired number of worker threads
            self._spawn_workers()

            # Wait for all of the workers to finish their work
            self._wait_for_work_to_finish()

            # Determine the elapsed time and print out a message stating how we got on
            self.elapsed_time = timestamp.get_elapsed_time(self.start_time)
            log.logger.debug("Finished processing {0} work items in {1}s [{2}.{3}()]".format(len(self.work_items), self.elapsed_time, self.func_ref.__module__, self.func_ref.__name__))

        # Special case to handle unjoined threads in workload
        except KeyboardInterrupt:
            for item in self.worker_pool:
                try:
                    # Adding sleep to see if it prevents Deadlock in the thread teardown
                    sleep_time = 1
                    log.logger.debug("Sleeping for {0} second before killing next thread.".format(sleep_time))
                    time.sleep(sleep_time)

                    item.terminate()
                except Exception as e:
                    log.logger.debug(str(e))
            raise KeyboardInterrupt

    def _populate_work_queue(self):
        """
        B{Populates the work queue with ThreadQueueEntry instances for each work item}

        """

        # Clear the done queue if required
        if not self.done_queue.empty():
            self.done_queue = Queue.Queue(len(self.work_items))

        # Populate the work queue with the work items
        for work_item in self.work_items:
            arg_list = [work_item]

            if self.additional_args is not None:
                # If self.additional_args is a list, simply add it to arg_list using a '+'  to keep the position state of the arguments
                if isinstance(self.additional_args, list):
                    arg_list = arg_list + self.additional_args

                # If self.additional_args is a dict, simply append it to arg_list
                elif isinstance(self.additional_args, dict):
                    arg_list.append(self.additional_args)

            # Create the work entry object
            work_entry = ThreadQueueEntry(self.func_ref, arg_list)
            self.work_queue.put(work_entry)
            self.work_entries.append(work_entry)

    def _spawn_workers(self):
        """
        B{Spawns the desired number of worker threads to work the work queue}

        """

        # Spawn threads to do the work
        for _ in range(self.num_workers):
            worker = multitasking.UtilitiesThread(target=_worker, args=(self.work_queue, self.done_queue))

            worker.func_ref = self.func_ref
            worker.start()
            self.worker_pool.append(worker)

    def _wait_for_work_to_finish(self):
        """
        B{Waits for work to finish by waiting for the work queue to empty and the done queue to fill and then joins the worker threads}

        """

        # Wait for all work items to be pulled from the work queue and enqueued in the done queue
        self._wait_for_done_queue_to_fill()

        # Attempt to join all workers
        log.logger.debug("Attempting to join all workers...")
        multitasking.wait_for_tasks_to_finish(self.worker_pool, timeout=self.task_join_timeout)

        # Figure out if any exceptions were raised during the queue execution
        self._process_exceptions()

    def _process_exceptions(self):
        """
        B{Checks if any of the worker entries raised an exception saving the results to the thread queue}
        """

        for work_entry in self.work_entries:
            if work_entry.exception_raised:
                self.exceptions_raised = self.exceptions_raised + 1
                self.exception_msgs.append(str(work_entry.exception_msg))
                self.exceptions.append(work_entry.exception)

    def _wait_for_done_queue_to_fill(self):
        """
        B{Loops and waits for the done queue to fill and periodically reports progress; will timeout if done queue does not fill within timeout}

        """

        work_queue_size = len(self.work_items)

        # Set a limit for how long we're willing to wait for the workers
        task_wait_timeout = 600
        timeout = self.task_wait_timeout if self.task_wait_timeout else task_wait_timeout * ((work_queue_size / len(self.worker_pool)) * 1.5)
        start_time = timestamp.get_current_time()
        wait_time = datetime.timedelta(seconds=timeout)
        elapsed_time = timestamp.get_current_time() - start_time
        loop_counter = 0

        # Compute the wait time in seconds
        wait_time_in_seconds = (wait_time.microseconds + (wait_time.seconds + wait_time.days * 24 * 3600) * 10 ** 6) / 10 ** 6

        while elapsed_time < wait_time:
            # If we have been told to exit, bail now
            if multitasking.should_workers_exit():
                return

            # Check to see if the done_queue is full (size matches the initial size of the work_queue)
            if self.done_queue.qsize() == work_queue_size:
                log.logger.debug("All work items have been processed and moved from work queue to done queue")
                break

            # If all of the workers are dead or stuck, break the loop
            num_active_workers = multitasking.get_num_tasks_running(self.worker_pool)
            if num_active_workers < 1:
                log.logger.debug("All workers have finished running. None is alive")
                break

            # Sleep a bit, update the elapsed time, and then loop again
            self.worker_pool = multitasking.join_tasks(self.worker_pool, .1)
            time.sleep(.1)
            elapsed_time = timestamp.get_current_time() - start_time
            loop_counter = loop_counter + 1

            # Give a periodic status update
            if loop_counter % 50 == 0:
                log.logger.debug("Workers are still working; done queue size: {0}/{1}; active workers: {2}/{3}; elapsed time: {4}/{5}s".format(self.done_queue.qsize(), work_queue_size, num_active_workers, self.num_workers, timestamp.get_elapsed_time(start_time), wait_time_in_seconds))
            if loop_counter % 100 == 0 and len(self.worker_pool) < 3:
                for worker in self.worker_pool:
                    log.logger.debug("  WORKER STILL RUNNING: {0}".format(worker.desc))

    def process_results(self, worker_entries):
        """
        B{Returns false if any of the worker entries were not successful}

        @type worker_entries: list <ThreadQueue.ThreadQueueEntry>
        @param worker_entries: The list of thread queue worker entires
        @rtype: boolean
        @return: False if any worker entry contains a False result
        """

        num_success = self._get_num_successful_results(worker_entries)
        return num_success == len(worker_entries)

    def _get_num_successful_results(self, worker_entries):
        """
        B{Returns the number of worker entries that have successful results}

        @rtype: int
        @return: The number of worker entries that were successful
        """

        total = 0
        for worker in worker_entries:
            if worker.result:
                total = total + 1

        return total


def _worker(work_queue, done_queue):
    """
    B{De-queues the object from the work queue and calls it's corresponding worker function, with its parameters. when finished, puts the object onto the done queue}

    @type work_queue: Queue
    @param work_queue: Queue of objects that have yet to be processed
    @type done_queue: Queue
    @param done_queue: Queue of objects that have been processed
    @rtype: void
    """

    while True:
        # Don't block when de-queuing to avoid any race conditions and potential process hanging
        try:
            work_entry = work_queue.get(timeout=.5)
            log.logger.debug("Processing next work item from work queue [{0} items remaining in work queue]".format(work_queue.qsize()))
        except Queue.Empty:
            break

        if work_entry is not None:
            # Get the function to execute
            function = work_entry.function

            # Get the function parameters
            parameters = work_entry.arg_list

            try:
                # Call the respective function maintaining positional parameters
                work_entry.result = function(*parameters)
            except Exception as e:
                exception.process_exception("Exception encountered by worker while invoking target")
                work_entry.exception_raised = True
                work_entry.exception_msg = e.args[0]
                work_entry.exception = e

            finally:
                log.logger.debug("Worker target invocation complete")
                work_entry.finished = True

            # Timebox the post processing operations so that the we don't hang here and cause a deadlock
            completion_level = 0
            loop_counter = 0

            while completion_level < 2 and loop_counter < 20:
                # Notify the work queue that we are done with the work_item and then put the work_item on the done queue
                if completion_level < 1:
                    try:
                        work_queue.task_done()
                        completion_level = 1
                    except:
                        exception.process_exception("Unable to mark work item as finished so that it can be dequeued from the work queue")

                # Populate the done queue with the finished work_items
                if completion_level < 2:
                    try:
                        done_queue.put(work_entry, timeout=.5)
                        completion_level = 2
                    except:
                        exception.process_exception("Unable to enqueue finished work item into done queue")

                loop_counter = loop_counter + 1

            # Report how we got on
            if completion_level == 2:
                log.logger.debug("Work item completed and placed on done queue")
            else:
                log.logger.debug("WARNING: Work item post-processing did not complete successfully within 10s timeout (completion level = {0})".format(completion_level))

            # If we have been told to exit, bail now
            if multitasking.should_workers_exit():
                if log.logger is not None:
                    log.logger.debug("Multitasking has signalled all workers to terminate, so worker is returning...")
                return

class CodeAllocator {
  constructor (sliceSize) {
    this.sliceSize = sliceSize;
    this.slicesPerPage = Process.pageSize / sliceSize;

    this.pages = [];
    this.free = [];
  }

  allocateSlice () {
    const slice = this.free.pop();
    if (slice !== undefined) {
      return slice;
    }

    return this._allocatePage();
  }

  _allocatePage () {
    const page = Memory.alloc(Process.pageSize);

    const { sliceSize, slicesPerPage } = this;

    for (let i = 1; i !== slicesPerPage; i++) {
      const slice = page.add(i * sliceSize);
      this.free.push(slice);
    }

    this.pages.push(page);

    return page;
  }

  freeSlice (slice) {
    this.free.push(slice);
  }
}

function makeAllocator (sliceSize) {
  return new CodeAllocator(sliceSize);
}

module.exports = makeAllocator;
